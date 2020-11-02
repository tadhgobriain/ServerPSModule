﻿#Requires -Version 5.0

Function Get-LoggedOnUser {
    <#
    .SYNOPSIS
        This function queries CIM on the local or a remote computer and returns the user (local or Active Directory) that is currently
        logged on.

    .EXAMPLE
        PS> Get-LoggedOnUser

        This would query the local computer and return the user logged on.
        
    .EXAMPLE
        PS> Get-LoggedOnUser -ComputerName CLIENT

        This would query the remote computer CLIENT and return the user logged on.

    .PARAMETER ComputerName
        The name of the computer you'd like to run this function against.
    #>

    [OutputType([PSCustomObject])]
    [CmdletBinding()]

    Param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String[]]$ComputerName = $env:COMPUTERNAME   
    )
    
    Begin {
        $ErrorActionPreference = 'Stop'
    }  
    Process {
        Try {
            ForEach ($Comp in $ComputerName){
                $Output = @{ 
                    ComputerName = $Comp 
                    UserName = 'Unknown'
                    ComputerStatus = 'Offline'
                }

                If (Test-Connection -ComputerName $Comp -Count 1 -Quiet) {
                    $Output.UserName = (Get-CimInstance -Class win32_computersystem -ComputerName $Comp).UserName
                    $Output.ComputerStatus = 'Online'
                }

                [PSCustomObject]$output
            }
        }
        Catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
} # END: Function Get-LoggedOnUser


Function Get-UserSecurityLog {
    # https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
    # https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    # https://stackoverflow.com/questions/50046370/extracting-from-the-message-in-powershell
    # http://duffney.io/AddCredentialsToPowerShellFunctions
    # 

    <#
    .Synopsis
        Retrieves security logs from a client PC relating to user logon/logoff events.
    .DESCRIPTION
        Long description
    .EXAMPLE
        Get-UserSecurityLog | Format-Table -Autosize
    .EXAMPLE
        Get-UserSecurityLog -ComputerName lab150-01 -Username 'administrator' -Days 7
    .EXAMPLE
        @('lab150-01','lab150-02') | Get-UserSecurityLog -Days 3
    .EXAMPLE
        $Password = ConvertTo-SecureString "password" -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential (".\administrator", $Password)
        Get-UserSecurityLog -ComputerName lab150-01 -Credential $Cred

    #>

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]

    Param (
        # Param1 help description
        [Parameter(Mandatory=$False,
            ValueFromPipeline=$True)]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        # Username help
        [Parameter(Mandatory=$False)]
        [String]$Username = '',

        # Days to look back must be between 1 and 30
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,30)]
        [Byte]$Days = 1,
 
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
                                                                       
    Begin {
        #Set the column width of the terminal window on the computer this script is run on (for Start-Transcript output)
        If( $Host -and $Host.UI -and $Host.UI.RawUI ) {
            $RawUI = $Host.UI.RawUI
            $OldSize = $RawUI.BufferSize
            $TypeName = $OldSize.GetType( ).FullName
            $NewSize = New-Object $TypeName (500, $OldSize.Height)
            $RawUI.BufferSize = $NewSize
        }

    $Date = (Get-Date).AddDays(-($Days))
    }
    Process {
        ForEach ($Computer in $ComputerName) {
            Try {
                $Logon = Get-WinEvent -FilterHashtable @{logname='security';id=4624;data=$UserName} -ComputerName $Computer -Credential $Credential -ErrorAction Stop |
                Where-Object { ($_.Properties[4].Value -like 'S-1-5-21-*') -and ((2,3,7,10,11) -contains $_.Properties[8].Value) -and ($_.TimeCreated -gt $Date) }  |
                Select-Object -Property TimeCreated,
                    @{label='UserName';expression={$_.properties[5].value}},
                    @{label='LogonType';expression={$_.properties[8].value}},
                    @{label='LogonProcessName';expression={$_.properties[9].value}},
                    @{label='AuthenticationPackage';expression={$_.properties[10].value}},
                    @{label='LogonID';expression={$_.properties[7].value}},
                    @{label='Linked LogonID';expression={$_.properties[25].value}},
                    @{label='ComputerName';expression={$_.properties[11].value}},
                    @{label='Domain';expression={($_.properties[6].value).split('.')[0]}},
                    @{label='Source IP';expression={$_.properties[18].value}},
                    @{label='Event';expression={"Logon"}}

                            
            $AccountLogoff = Get-WinEvent -FilterHashtable @{logname='security';id=4634} -ComputerName $Computer -Credential $Credential |       
                Where-Object { ($_.Properties[0].Value -like 'S-1-5-21-*') -and ($_.TimeCreated -gt $Date) } |
                Select-Object -Property TimeCreated,
                    @{label='UserName';expression={$_.properties[1].value}},
                    @{label='LogonType';expression={$_.properties[4].value}},
                    @{label='LogonID';expression={$_.properties[3].value}},
                    @{label='Domain';expression={$_.properties[2].value}},
                    @{label='Event';expression={"AccountLogoff"}}
        
        
            $UserInitiatedLogoff = Get-WinEvent -FilterHashtable @{logname='security';id=4647} -ComputerName $Computer -Credential $Credential |
                Where-Object { ($_.Properties[0].Value -like 'S-1-5-21-*') -and ($_.TimeCreated -gt $Date) } |
                Select-Object -Property TimeCreated,
                    @{label='UserName';expression={$_.properties[1].value}},
                    @{label='LogonID';expression={$_.properties[3].value}},
                    @{label='Domain';expression={$_.properties[2].value}},
                    @{label='Event';expression={"UserInitiatedLogoff"}}

            }
            Catch {
               $_.Exception.Message
            }  
        }
    }
    End {
        $Logs = $Logon + $AccountLogoff + $UserInitiatedLogoff

        $Logs | ForEach-Object {
            If ($_.LogonType -eq '2') { $_.LogonType = 'Interactive' }
            ElseIf ($_.LogonType -eq '3') { $_.LogonType = 'Network' }
            ElseIf ($_.LogonType -eq '7')  { $_.LogonType = 'Unlock' }
            ElseIf ($_.LogonType -eq '8')  { $_.LogonType = 'Probable IIS' }
            ElseIf ($_.LogonType -eq '10')  { $_.LogonType = 'RemoteInteractive' }
            ElseIf ($_.LogonType -eq '11')  { $_.LogonType = 'CachedInteractive' }
        }
        
        $Logs
    }
} # END: Function Get-UserSecurityLog


Function Reset-NetworkAdapter {
    <#
    .Synopsis
    Short description
    .DESCRIPTION
    Long description
    .EXAMPLE
    Reset-ITTNetworkAdapter -LabName lab220, lab229
    .EXAMPLE
    "lab216","lab220" | Reset-ITTNetworkAdapter 
    #>

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    
    Param (
        # A list or an array of type string
        [Parameter(Mandatory=$True,
                   ValueFromPipeline=$True)]
        [String[]]$LabName 
    )
   
    Begin {
        $IPType = 'IPv4' 
        Write-Verbose 'Checking computer name...'
    }   
    Process { 
        ForEach ($Lab in $LabName) { 
        If ($env:COMPUTERNAME -like "$Lab*") { 
            Write-Verbose "Matched lab $Lab, check dhcp and enable if required"
                                                    
            # Enabling the physical adapter if it is 'DISABLED' to determine if it is 'DISCONNECTED' or 'UP'
            Get-NetAdapter -Physical | Where-Object Status -Eq 'Disabled' | Enable-NetAdapter

            $AdapterUp = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' # 'Up' means NIC 'CONNECTED' and adapter 'ENABLED'

            If ($AdapterUp) { 
                # If the adapter name was changed, rename it to 'Ethernet'
                If ($AdapterUp.Name -ne 'Ethernet') { 
                        $AdapterUp | Rename-NetAdapter -NewName 'Ethernet' -Confirm:$False
                        $AdapterUp.Name = 'Ethernet'
                } 

                $Interface = $AdapterUp | Get-NetIPInterface -AddressFamily $IPType

                If (!$Interface.Dhcp) {
                    Write-Verbose "DHCP disabled"
                    # Remove existing static gateway if it exists
                    If (($Interface | Get-NetIPConfiguration).Ipv4DefaultGateway) { $Interface | Remove-NetRoute -Confirm:$False }                                                                     

                    # Enable DHCP
                    Write-Verbose "Setting DHCP on..."
                    $Interface | Set-NetIPInterface -DHCP Enabled -Verbose -Confirm:$False

                    # Configure the  DNS Servers automatically
                    Write-Verbose "Setting DNS to automatic via DHCP"
                    $Interface | Set-DnsClientServerAddress -ResetServerAddresses -Verbose -Confirm:$False

                    # Set WINS statically
                    Netsh interface ip set winsservers name=$($Adapter.name) static 193.1.120.4

                    # Restart the network adapter
                    Write-Verbose "Restarting network adapter $($Adapter.Name)"
                    $Adapter | Disable-NetAdapter -Verbose -Confirm:$False
                    Start-Sleep -Seconds 5
                    $Adapter | Enable-NetAdapter -Verbose -Confirm:$False
                    Write-Verbose 'Network adapter reset complete'
                }                                                         
                Else { Write-Verbose 'DHCP already enabled'}
                
            }                                                                   
            Else { Write-Verbose 'Network cable not connected, leaving as is' }
                                                                                   
        }
        Else { Write-Verbose "Not matching network lab $Lab, leaving network adapter unchanged" }  
        }                 
    }  
} # End: Function Reset-NetworkAdapter


Function Get-TUDUser {
<#
.Synopsis
Short description
.DESCRIPTION
ToDo: Need to have $Identity as an output to pipe into Reset-ITTUser
.EXAMPLE
Get-TUDUser -Identity X00058529
.EXAMPLE
'X00058529','X10001012' | Get-TUDUser -CopyToClipboard
.INPUTS
Inputs to this cmdlet (if any)
.OUTPUTS
Output from this cmdlet (if any)
.NOTES
General notes
.COMPONENT
The component this cmdlet belongs to
.ROLE
The role this cmdlet belongs to
.FUNCTIONALITY
The functionality that best describes this cmdlet
#>

[CmdletBinding(PositionalBinding=$False,
                ConfirmImpact='Medium')]
[OutputType([String])]

Param (
    # Param1 help description
    [Parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True)]
    [ValidatePattern('^x[0-9]{8}$')]
    [String[]]$Identity,

    # Param2 help description
    [Parameter(Mandatory=$False)]
    [String]$OraclePwd = 'Z3ggySt1rd5st',

    # Param3 help description
    [Parameter(Mandatory=$False)]
    [Switch]$CopyToClipboard
)

Begin {
    If (!(Test-Path -Path "$env:ProgramFiles\PackageManagement\NuGet\Packages\Oracle.ManagedDataAccess*")) {
        Write-Output 'Oracle Managed Driver not installed'
        Write-Output 'Please run PS command 'Install-ODPNetManagedDriver''
    }
    Else {
        # Load the ODP.NET assembly into Powershell 
        Add-Type -Path "$env:ProgramFiles\PackageManagement\NuGet\Packages\Oracle.ManagedDataAccess.$($(Get-Package -Name Oracle.ManagedDataAccess).Version)\lib\net40\Oracle.ManagedDataAccess.dll"  
    }

    # $SearchDCs = @('compdc1.computing.stu.it-tallaght.ie','studc1.stu.it-tallaght.ie','engdc1.eng.stu.it-tallaght.ie')
    $GCName = (Get-ADDomainController -Discover -Service 'GlobalCatalog').HostName
    $TargetGC = "$GCName" + ":3268"

    $TextInfo = (Get-Culture).TextInfo

    $ExtensionAttribute15 = 'TUDublin'
    
    $COREconnString = "User id=itt_viewer;Password=""hug67*="" ;Connection Timeout=60;Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=193.1.122.12)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=core22)))"
    $CompDBconnString ="User id=AdminScripts; Password=$OraclePwd; Connection Timeout=60; Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=10.10.2.7)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=GLOBAL1))); Min Pool Size=10; Connection Lifetime=120; Connection Timeout=60; Incr Pool Size=5; Decr Pool Size=2; Max Pool Size=100; Validate Connection=True"

    # Create tables 
    $CORETable = New-Object System.Data.DataTable 'CORE Results'
    $UserTable = New-Object System.Data.DataTable 'Results'

    # Define and add the columns
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Correct Domain',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'ADAccount',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'LastLogonDate',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'PasswordExpired',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Office365 Parameters',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Office365 Licence',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Office365 GUID',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'EmailAddress',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DataRetentionPolicy',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'ID',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Firstname',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Lastname',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Password',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Year',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Programme',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'RegCode',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Account Action',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Term',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Last Update (CORE)',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount_Status',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount_DefaultPwd',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Action',([String])))

    $ActionType = @{ 
        'NoAction' = @'
No action is necessary at this time.
'@
        'ADAccountNotCreatedYet' = @'
The AD account has not been created yet. Please wait 1 hour and run 'Get-TUDUser' again.
'@
        'NotRegistered' = @'
Email body to student:

According to our records you are not currently registered.

Please contact the Registrars/Part-Time/Finance office and clarify if there is a delay, or if there is something outstanding that they require from you.

https://www.tudublin.ie/for-students/student-services-and-support/student-information-desks

An account will be setup automatically once your registration is complete.
'@
        'AccountDisabled' = @'
Email body to student:

According to our records there are outstanding issues with your registration.

As a result of this your account has been automatically disabled.

You will need to contact the Registrars/Part Time office to resolve this matter.

Once these issues are resolved, your account will then be enabled again automatically. 

https://www.tudublin.ie/for-students/student-services-and-support/student-information-desks

If you are still have difficulties with your account following that, please contact us again if you require a password reset etc.
'@
        'NoBirthdate' = @'
Email body to student:

According to our records there are outstanding issues with your registration.

A birthdate is not recorded in our systems.

As a result of this your account has been not been setup.

You will need to contact the Registrars/Part Time office to resolve this matter.

Once these issues are resolved, your account will then be setup automatically. 

https://www.tudublin.ie/for-students/student-services-and-support/student-information-desks

If you are still have difficulties with your account following that, please contact us again if you require a password reset etc.
'@
        'Part-time EL student' = @'
For 2020 academic year, AD user accounts are created for part-time students who are 'EL' registered.                
'@
        'ProgrammeCodeNotInFIM' = @'
Email body to IT Services: 
    The programme code associated with this student is not registered in FIM. Please add the following programme code to the SQL lookup table in FIM.
'@
        'Duplicate account (comp)' = @'
There is a duplicate AD account in another domain.
Once this duplicate account is deleted a new account will be created automatically in the Computing domain.
The Office365 GUID attached to the duplicate AD account will need to be noted and set in the newly created AD account.
Use 'Set-ADuser -Identity -Guid' for this purpose.
Email: itsupport.tallaght@tudublin.ie or ElecTechSupport.Tallaght@TUDublin.ie: 

Email body:
     I would be grateful if you would delete an old duplicate account in your domain.
     We have noted and will attach the existing Office365 GUID to the new AD account in the Computing domain.
     The student details are: 
'@
        'Duplicate account' = @'
There is a duplicate AD account in another domain.
The Office365 GUID attached to the duplicate AD account will need to be noted and set in the newly created AD account.
Use 'Set-ADuser -Identity -Guid' for this purpose.
Email: itsupport.tallaght@tudublin.ie or ElecTechSupport.Tallaght@TUDublin.ie: 

Email body:
     I would be grateful if you would delete an old duplicate account in your domain.
     We have noted and will attach the existing Office365 GUID to the new AD account in the local domain.
     The student details are: 
'@
        'RX account' = @'
This student is registered for exam purposes only but may have discretionary logon access.
Please check 'valid domain user definition' to see when this discretionary access expires.

Email body to student: 

     You are currently registered for exams only and do not have logon access.
     If you believe this is incorrect, please contact the Registrars/Part-Time/Finance office for further assistance.

     https://www.tudublin.ie/for-students/student-services-and-support/student-information-desks
'@
    }
}
Process {
    Write-Output `n

    ForEach ($Id in $Identity) {
        $Id = $TextInfo.ToTitleCase($Id)

        $COREsqlString = @" 
            SELECT ID, FIRSTNAME, LASTNAME, TO_CHAR(BIRTHDATE, 'DDMonYY') AS PASSWORD, YEARATT, PROGRAMME, REGCODE, ACCOUNT_ACTION, SUBSTR(TERM,1,4) AS TERM, LAST_UPDATED_DATE_TIME AS LAST_UPDATE

            FROM ITT_STUDENT   
            
            WHERE ID LIKE '$Id'                    
"@

        $TUDUser = $UserTable.NewRow()

        $TUDUser.Action = $ActionType.Get_Item('NoAction')

        Get-DBResult  $COREconnString $COREsqlString $CORETable
            
        $RegUser = $CORETable.Rows | Where-Object ID -Like $Id
        If ($RegUser) {
            $TUDUser.ID = $RegUser.ID
            $TUDUser.Firstname = $RegUser.FIRSTNAME
            $TUDUser.Lastname = $RegUser.LASTNAME
            $TUDUser.Password = $RegUser.PASSWORD
            $TUDUser.Year = $RegUser.YEARATT

            If ($RegUser.PROGRAMME -eq 'TA_HHUMN_ERB' -or ($RegUser.Programme).Substring(3,3) -eq 'ERA') {
                $TUDUser.Programme = $RegUser.PROGRAMME + ' (Erasmus)' }
            Else { $TUDUser.Programme = $RegUser.PROGRAMME }

            # Establish correct domain based on programme code
            # EngProgCodes: 'TA_E*','FS_C*', not 'TA_ERA*'
            # CompProgCodes: 'TA_S*','TA_K*','FS_S*'
            # StuProgCodes: 'TA_A*','TA_B*','TA_H*','TA_ERA*' 
            If (($TUDUser.Programme -like 'TA_E*') -or ($TUDUser.Programme -like 'FS_C*') -and ($TUDUser.Programme -notlike 'TA_ERA*')) {
                $TUDUser.'Correct Domain' = 'Eng'
            } 
            If ($TUDUser.Programme -like 'TA_S*' -or $TUDUser.Programme -like 'TA_K*' -or $TUDUser.Programme -like 'FS_S*') {
                $TUDUser.'Correct Domain' = 'Computing'
            }
            If (($TUDUser.Programme -like 'TA_A*') -or ($TUDUser.Programme -like 'TA_B*') -or ($TUDUser.Programme -like 'TA_H*') -or ($TUDUser.Programme -like 'TA_ERA*')) {
                $TUDUser.'Correct Domain' = 'Stu'
            }

            
            $TUDUser.RegCode = $RegUser.REGCODE
            $TUDUser.'Account Action' = $RegUser.ACCOUNT_ACTION
            $TUDUser.Term = $RegUser.TERM
            $TUDUser.'Last Update (CORE)' = $RegUser.LAST_UPDATE

            If ($TUDUser.'Account Action' -eq 'DISABLE') { $TUDUser.Action = $ActionType.Get_Item('AccountDisabled') }
            If (!$TUDUser.Password -and $TUDUser.ID ) { $TUDUser.Action = $ActionType.Get_Item('NoBirthdate') }
            
            If ($TUDUser.REGCODE -eq 'RX' ) { $TUDUser.Action = $ActionType.Get_Item('RX account') }
        }
        Else { 
            $TUDUser.Action = $ActionType.Get_Item('NotRegistered') 
        }
        
        <#$DC = 0
        Do {
            $ADUser = Get-ADUser -Filter "SamAccountName -Like '$ID'" -Properties Company,Office,EmailAddress,ExtensionAttribute2,ExtensionAttribute15,ProxyAddresses,LastLogonDate,PasswordExpired,MemberOf,mS-DS-ConsistencyGuid -Server $SearchDCs[$DC]
            $DC = $DC + 1
        } While (($Null -eq $ADUser) -and ($DC -le ($SearchDCs.Count)-1))
        #>
        #$CurrentDomain = $SearchDCs[$DC-1].Split('.')[1]
        

        # Search global catalogue for the AD user account(s)
        $ADUser = Get-ADUser -Filter "SamAccountName -Like '$ID'" -Properties Company,Office,EmailAddress,ExtensionAttribute2,ExtensionAttribute15,ProxyAddresses,LastLogonDate,PasswordExpired,MemberOf,mS-DS-ConsistencyGuid -Server $TargetGC
        $DN = $ADUser.DistinguishedName
        $CurrentDomain = ($DN.Substring($dn.IndexOf("DC=")).split(',') | select -First 1).split('=')[-1]

        If ( ($Null -eq $ADuser) -and $RegUser ) { $TUDUser.Action = $ActionType.Get_Item('ADAccountNotCreatedYet')  }

        If ($ADUser) { 
            # Check for AD account in another domain
            If ( $RegUser -and ($TUDUser.'Correct Domain' -eq 'Computing') -and ($TUDUser.'Correct Domain' -ne $CurrentDomain)) { $TUDUser.Action = $ActionType.Get_Item('Duplicate Account (comp)')  }
            ElseIf ( $Reguser -and ($TUDUser.'Correct Domain' -ne 'Computing') -and $TUDUser.'Correct Domain' -ne $CurrentDomain  ) { $TUDUser.Action = $ActionType.Get_Item('Duplicate Account') }
            
            $TUDUser.ADAccount = $CurrentDomain + '\' + $ADUser.SamAccountName
            $TUDUser.LastLogonDate = $ADUser.LastLogonDate
            $TUDUser.PasswordExpired = $ADUser.PasswordExpired
            If (($TUDUser.'Correct Domain' -ne 'computing') -and ($TUDUser.PROGRAMME -like 'TA_K*' -or $TUDUser.PROGRAMME -like 'TA_S*' -or $TUDUser.PROGRAMME -like 'FS_S*')){
                $TUDUser.Action = $ActionType.Get_Item('Duplicate Account')
            }

            $CorrectProxyAddresses = @("SMTP:$($ADUser.EmailAddress)", "smtp:$($ADUser.SamAccountName)@myTUDublin.mail.onmicrosoft.com","sip:$($ADUser.EmailAddress)")
            $ProxyTest1 = ($ADUser.ProxyAddresses -contains $CorrectProxyAddresses[0]) -and ($ADUser.ProxyAddresses -contains $CorrectProxyAddresses[1]) -and ($ADUser.ProxyAddresses -contains $CorrectProxyAddresses[2])
            $ProxyTest2 = (($ADUser.ProxyAddresses -clike 'SMTP*').count -eq 1)
            
            $Office365Test = ($ADUser.EmailAddress -eq "$($ADUser.SamAccountName)@mytudublin.ie") -and ($ADUser.ExtensionAttribute15 -eq $ExtensionAttribute15) -and $ProxyTest1 -and $ProxyTest2
            $TUDUser.'Office365 Parameters' = $Office365Test

            $Office365Licence = $ADUser.MemberOf | Where-Object {($_ -like '*A3*') -or ($_ -like '*A1*')}
            If ($Office365Licence -like '*A3*') { $Office365Licence = 'A3'}
            ElseIf ($Office365Licence -like '*A1*') { $Office365Licence = 'A1'}
            Else {$Office365Licence = 'No'}
            $TUDUser.'Office365 Licence' = $Office365Licence

            If ($Null -ne ($ADUser.'mS-DS-ConsistencyGuid')) { 
                $TUDUser.'Office365 GUID' = Convert-ByteArrayToString ($ADUser.'mS-DS-ConsistencyGuid')
            }
            Else {$TUDUser.'Office365 GUID' = 'False'}

            If ($TUDUser.'Office365 Licence' -eq 'No' -and $TUDUser.'Office365 Parameters' -and $TUDUser.'Office365 GUID' -eq 'True' -and $TUDUser.'Current Domain' -eq 'computing') { 
                $TUDUser.Action = $ActionType.Get_Item('GroupNotInFIM') 
            }

            $TUDUser.EmailAddress = $ADUser.EmailAddress
            
            If ($Null -eq $ADUser.extensionAttribute2){
                $TUDUser.DataRetentionPolicy = 'N/A'
            }
            ElseIf ($ADUser.extensionAttribute2){
                $TUDUser.DataRetentionPolicy = $ADUser.extensionAttribute2 
            }       
    #region ComputingDB Account 
            # If Computing, check their DB account
            If (($TUDUser.'Current Domain' -eq 'computing') -and ($TUDUser.PROGRAMME -like 'TA_K*')){
                $CompDBsqlString = @" 
                        SELECT Username,Account_Status FROM dba_users WHERE username LIKE `'$Id`'
"@

                # Check is the Oracle password provided as an argument
                If ( $OraclePwd ) {
                    # Check is the Oracle password provided correct in
                    $CompDBUserTable = New-Object System.Data.DataTable 'CompDB Results'
                
                    Get-DBResult  $CompDBconnString $CompDBsqlString $CompDBUserTable
                
                    If ($CompDBUserTable.Username) { 
                        $TUDUser.DBAccount = $CompDBUserTable.Username
                        $TUDUser.DBAccount_Status = $CompDBUserTable.Account_Status
                        $TUDUser.DBAccount_DefaultPwd = "db$($TUDUser.Password)"

                        $CompDBUserTable.Clear()
                    }
    
                    Else { $CompDBUserTable
                        $TUDUser.DBAccount = 'No account setup as yet'
                        $TUDUser.DBAccount_Status = 'N/A'
                        $TUDUser.DBAccount_DefaultPwd = 'N/A'
                    }
                }
            }               
#endregion                              
        }
        $UserTable.Rows.Add($TUDUser)

        $CORETable.Clear()
    }   
}
End {
    Write-Output "CORE provides the valid details of a student."
    Write-Output "For a valid domain user definition, please visit https://github.com/tadhgobriain/Snippets"
    Write-Output "A student that is DISABLE in CORE will always have a DISABLED AD account."
    Write-Output "A student that is ENABLE in CORE may be DISABLED in AD (see valid domain user definition).`n"

    Write-Output "For links and guides on how to access IT resources, please visit"
    Write-Output "https://www.tudublin.ie/for-students/student-login/tallaght"
    
    $UserTable

    #CopyToClipboard?
    If ($CopyToClipboard) { 
        $OutputArray = New-Object System.Collections.Generic.List[System.Object]
        ForEach ($Row in $UserTable.Rows) {
            $OutputArray.Add($Row.EmailAddress)
            $OutputArray.Add('Hi ' + $Row.Firstname + ',')
            $OutputArray.Add($Row.Action)
        }

        Set-Clipboard $OutputArray
    }
}
} # End: Function Get-TUDUser


Function Get-TUDUserLastLogon {
    <#
    .Synopsis
    Get-TUDUserLastLogon gets the last logon of an Active Directory user
    .DESCRIPTION
    ToDo:
    .EXAMPLE
    Get-TUDUserLastLogon -Identity x12345678
    .EXAMPLE
    'X00058529','X10001012' | Get-TUDUserLastLogOn
    .INPUTS
    Provide the StudentID in the form <x12345678> (case-insensitive)
    .OUTPUTS
    Output from this cmdlet (if any)
    .NOTES
    Each domain controller is queried separately to calculate the last logon from all results of all non-Azure DCs in a domain.
    .COMPONENT
    The component this cmdlet belongs to
    .ROLE
    The role this cmdlet belongs to
    .FUNCTIONALITY
    The functionality that best describes this cmdlet
    #>
    
    [CmdletBinding(PositionalBinding=$False,
    ConfirmImpact='Medium')]
    [OutputType([String])]
    
    Param (
        # Param1 help description
        [Parameter(Mandatory=$True,
        Position=0,
        ValueFromPipeline=$True)]
        [ValidatePattern('^x[0-9]{8}$')]
        [String[]]$Identity
    )
     
    Begin {
        $TextInfo = (Get-Culture).TextInfo
    
        # Users only authenticate against local site DCs for AD.
        # For Office365, wireless, Moodle (more to come), users authenticate using SSO against AAD (a different forest).
        $DomainDC = Get-ADDomainController -Filter * | Where-Object Site -ne 'AzureAD'  
    
        # Create result table
        $UserTable = New-Object System.Data.DataTable 'Results'
        # Create table for instance of user on each DC
        $UserInstanceDCTable = New-Object System.Data.DataTable 'Instances'
    
        # Define and add the columns
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'ID',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Firstname',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Lastname',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Description',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'LastLogon',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'LastIntLogon',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Logon DC',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Notes',([String])))

        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'ID',([String])))
        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'Firstname',([String])))
        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'Lastname',([String])))
        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'Description',([String])))
        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'LastLogon',([String])))
        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'LastIntLogon',([String])))
        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'Logon DC',([String])))
        $UserInstanceDCTable.Columns.Add((New-Object System.Data.DataColumn 'Notes',([String])))
    }
    
    Process {    
        ForEach ($Id in $Identity) {
            $Id = $TextInfo.ToTitleCase($Id)
    
            $TUDUser = $UserTable.NewRow()
    
            $AccountExist = DSQuery User -samid $Id
            If ($AccountExist) { 
                ForEach ($DC in $DomainDC) {

                    $UserInstanceDC = $UserInstanceDCTable.NewRow()

                    Try {
                        $SearchUser = Get-ADUser $Id -Server $DC -Properties Description,LastLogon,msDS-LastSuccessfulInteractiveLogonTime -ErrorAction Stop
    
                        $UserInstanceDC.ID            = $SearchUser.SamAccountName
                        $UserInstanceDC.Firstname     = $SearchUser.GivenName
                        $UserInstanceDC.Lastname      = $SearchUser.Surname
                        $UserInstanceDC.Description   = $SearchUser.Description
                        $UserInstanceDC.'Logon DC'    = $DC.Name
                        $UserInstanceDC.LastLogon     = [datetime]::FromFileTime($SearchUser.LastLogon)
                        $UserInstanceDC.LastIntLogon  = [datetime]::FromFileTime($SearchUser.'msDS-LastSuccessfulInteractiveLogonTime')

                        $UserInstanceDCTable.Rows.Add($UserInstanceDC)
                    }
                    Catch {
                        Write-Warning "No reports from $($dc)!"
                    }
                }

                $UserLastLogonDC = $UserInstanceDCTable | Where-Object {$_.lastlogon -NotLike '*1601*'} | Sort-Object LastLogon -Descending | Select-Object -First 1
                
                If ($UserLastLogonDC) {
                    $TUDUser.ID                         = $UserLastLogonDC.ID
                    $TUDUser.Firstname                  = $UserLastLogonDC.FirstName
                    $TUDUser.Lastname                   = $UserLastLogonDC.Lastname
                    $TUDUser.Description                = $UserLastLogonDC.Description
                    $TUDUser.LastLogon                  = $UserLastLogonDC.LastLogon
                    $TUDUser.LastIntLogon               = $UserLastLogonDC.LastIntLogon
                    $TUDUser.'Logon DC'                 = $UserLastLogonDC.'Logon DC'
                }
                
                Else {
                    #Write-Warning "No reports for user $($user.name). Possible reason: No first login."
                    $TUDUser.ID                         = $SearchUser.SamAccountName
                    $TUDUser.Firstname                  = $SearchUser.GivenName
                    $TUDUser.Lastname                   = $SearchUser.Surname
                    $TUDUser.Description                = $SearchUser.Description
                    $TUDUser.Notes                      = 'No initial login'
                }

                $UserInstanceDCTable.Clear()
            }
            Else {
                $TUDUser.Notes = 'User account does not exist'
            }
            
            $UserTable.Rows.Add($TUDUser)
        }
    }
    
    End {
        $UserTable
    }   
} # End: Function Get-TUDUserLastLogon


Function Reset-TUDUser {
    <#
    .Synopsis
    Reset AAD user account using specific AAD DC
    .DESCRIPTION
    Long description
    .EXAMPLE
    Reset-TUDUser -Identity
    .EXAMPLE
    Another example of how to use this cmdlet
    .INPUTS
    Inputs to this cmdlet (if any)
    .OUTPUTS
    Output from this cmdlet (if any)
    .NOTES
    General notes
    .COMPONENT
    The component this cmdlet belongs to
    .ROLE
    The role this cmdlet belongs to
    .FUNCTIONALITY
    The functionality that best describes this cmdlet
    #>

    [CmdletBinding( SupportsShouldProcess=$True, 
                    PositionalBinding=$False,
                    ConfirmImpact='Medium')]
    [OutputType([String])]

    Param (
        # Param1 help description
        [Parameter(Mandatory=$True,
                   Position=0,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [ValidatePattern('^x[0-9]{8}$')]
        [String[]]$Identity,

        # Param2 help description
        [Parameter(Mandatory=$False)]
        [Switch]$SkipChangeOnNextLogin
    )

    Begin {
        $TextInfo = (Get-Culture).TextInfo
        $AzureDC = 'tadco03.computing.stu.it-tallaght.ie'
    }
    Process {
        ForEach ($Id in $Identity) {
            $Id = $TextInfo.ToTitleCase($Id)
            $DefaultPassword = (Get-TUDUser -Identity $ID).Password

            If ($PSCmdlet.ShouldProcess($ID)){
                $Student = Get-ADUser -Filter "SamAccountName -like '$Id'"
                Set-ADAccountPassword -Identity $ID -NewPassword ( ConvertTo-SecureString -AsPlainText $DefaultPassword -Force) -Server $AzureDC
                If (!$SkipChangeOnNextLogin) { $Student | Set-ADUser -ChangePasswordAtLogon $True }
                Else {
                    $Student | Set-ADUser -ChangePasswordAtLogon $False
                }
            }
        }    
    }
    End {
    
    }
} # End: Function Reset-TUDUser


Function Set-TUDUser {
    <#
    .Synopsis
    Set AAD user account using specific AAD DC
    .DESCRIPTION
    Set AAD user account using specific AAD DC, specifically the email GUID, a 16-digit hex value, in string format.
    .EXAMPLE
    Set-TUDUser -Identity x12345678 -GUID '01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10'
    .EXAMPLE
    Another example of how to use this cmdlet
    .INPUTS
    Inputs to this cmdlet (if any)
    .OUTPUTS
    Output from this cmdlet (if any)
    .NOTES
    Get-ADUser returns a byte array, but Set-ADUser needs a GUID.
    .COMPONENT
    The component this cmdlet belongs to
    .ROLE
    The role this cmdlet belongs to
    .FUNCTIONALITY
    The functionality that best describes this cmdlet
    #>

    [CmdletBinding( SupportsShouldProcess=$True, 
                    PositionalBinding=$False,
                    ConfirmImpact='Medium')]
    [OutputType([String])]

    Param (
        # Param1 help description
        [Parameter(Mandatory=$True,
                   Position=0,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [String[]]$Identity,

        # Param2 help description
        [Parameter(Mandatory=$True,
                   Position=1,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [String]$msdsGUID,

        # Param2 help description
        [Parameter(Mandatory=$False)]
        [Switch]$Force
    )

    Begin {
        $AzureDC = 'tadco03.computing.stu.it-tallaght.ie'
    }
    Process {
        ForEach ($Id in $Identity) {
            If ($Identity -notmatch '^x[0-9]{8}$') {
                Throw "ERROR: $Identity is not valid. Enter a name that begins with an 'x' or 'X' and ends with a eight-digit number."
            }
            If ($msdsGUID -notmatch '^([0-9a-z]{2}\s){15}[0-9a-z]{2}$') {
                Throw "ERROR: $msdsGUID is not valid. Enter a ms-ds-consistency guid that is a string containing 16 space-seperated 2-digit hex values."
            }

            If ($PSCmdlet.ShouldProcess($ID)){
                $Student = Get-ADUser -Filter "SamAccountName -eq '$Id'" -Property mS-DS-ConsistencyGuid
                If (!$Force -and $Student.'mS-DS-ConsistencyGuid') {
                    Write-Warning "User $ID already has an ms-ds-consistency GUID assigned."
                    Write-Warning "GUID: $(Convert-ByteArrayToString ($Student.'mS-DS-ConsistencyGuid'))"
                    Write-Warning "Use -force to overwrite value."
                }
                ElseIf ($Force -and $Student.'mS-DS-ConsistencyGuid'){         
                    Write-Warning "Overwriting existing GUID on user $ID"
                    Write-Warning "Old GUID: $(Convert-ByteArrayToString ($Student.'mS-DS-ConsistencyGuid'))"
                    $UsermsdsGUID = Convert-StringToGUID ($msdsGUID)
                    $Student | Set-ADUser -Replace @{'ms-ds-ConsistencyGUID' = $UsermsdsGUID} -Server $AzureDC
                }
                Else {
                    $UsermsdsGUID = Convert-StringToGUID ($msdsGUID)
                    $Student | Set-ADUser -Add @{'ms-ds-ConsistencyGUID' = $UsermsdsGUID} # Need to do it on local DC
                }
            }
        }    
    }
    End {  
    }
} # End: Function Set-TUDUser

Function Get-DBResult {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateScript({$_ -match '\bdata source\b'})]
        [string]$ConnString,

        [ValidateScript({$_ -match '\bselect\b'})]
        [Parameter(Mandatory=$True)]
        [string]$SqlString,

        [Parameter(Mandatory=$True)]
        [System.Data.DataTable]$DataTable
    )

    Try {
        $Conn = New-Object Oracle.ManagedDataAccess.Client.OracleConnection($ConnString)

        $Cmd=$Conn.CreateCommand()

        $Cmd.CommandText= $SqlString
 
        $Da = New-Object Oracle.ManagedDataAccess.Client.OracleDataAdapter($Cmd)

        # Fill() method will “open” and “close” the database connection as part of its normal operation
        $Da.Fill($DataTable) | Out-Null    
    }
    Catch {
        Write-Error ("Can't open connection: {0}`n{1}" -f `
        $Conn.ConnectionString, $_.Exception.ToString())
    }
    Finally {
        # Cleanup
        If ($Conn.State -eq 'Open') { 
            $Cmd.Dispose()
            $Conn.Close()
        }
    }   
} # END: Function Get-DBResult


Function Test-Verbose {
[CmdletBinding()]
Param()
	[System.Management.Automation.ActionPreference]::SilentlyContinue -ne $VerbosePreference
} # END: Function Test-Verbose


Function Install-ODPNetManagedDriver {
    <#
    .Synopsis
    Short description
    .DESCRIPTION
    Long description
    .EXAMPLE
    Install-ODPNetManagedDriver
    #>

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]

    Param (
        # Param help description
        [Parameter(Mandatory=$False)]
        [Switch]$Force
    )

    Set-StrictMode -Version Latest
    
    If (!(Test-Path -Path "$env:ProgramFiles\PackageManagement\NuGet\Packages\Oracle.ManagedDataAccess*")) {
        Write-Output 'Installing Oracle Managed Driver...'
        If ($Null -eq (Get-PackageProvider -Name NuGet)) { 
            Install-PackageProvider -Name NuGet -Verbose | Out-Null 
        }
    
        If ($Null -eq (Get-PackageSource -Name NuGet -ErrorAction SilentlyContinue)) { 
            Register-PackageSource -Name NuGet -ProviderName NuGet -Location 'https://www.nuget.org/api/v2/' -Verbose
        }
    
        If ($Null -eq (Get-Package -Name Oracle.ManagedDataAccess -ErrorAction SilentlyContinue)) {
            Find-Package -Name Oracle.ManagedDataAccess -ProviderName NuGet | Install-Package -Scope AllUsers -Force -Verbose
            Write-Output 'Installation of Oracle Managed Driver complete'
        }
    }
    Else { Write-Output 'Oracle Managed Driver already installed.' }     
} # END: Function Install-ODPNetManagedDriver


Function Import-Credential {

} # END: Function Import-Credential


Function Export-Credential {

} # END: Function Export-Credential


Function Convert-StringToGUID ($msdsGuidString) {
    $HexArray = $msdsGuidString -Split(' ') -replace '..','0x$&' -ne ''
    [byte[]]$ByteArray = ForEach ($Hex in $HexArray){ [uint32]$Hex }
    $GUID = [guid]$ByteArray

    Return $GUID
} # END: Function Convert-StringToGUID

Function Convert-ByteArrayToString ($msdsGuid) {
    $msdsGuidString = [string]::Join(" ",($msdsGuid | ForEach-Object {$_.ToString("X2")}))
    Return $msdsGuidString
} # END: Function Convert-ByteArrayToString


Export-ModuleMember -Function Export-Credential, Get-LoggedOnUser, Get-TUDUser, Get-TUDUserLastLogon, Get-UserSecurityLog, Install-ODPNetManagedDriver, Reset-NetworkAdapter, Reset-TUDUser, Set-TUDUser