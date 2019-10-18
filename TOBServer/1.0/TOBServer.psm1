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
    Get-TUDUser -Identity
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

        # Param3 help description
        [Parameter(Mandatory=$False)]
        [Switch]$CopyToClipboard
    )

    Begin {
        Set-ODPNetManagedDriver

        $SearchDCs = @('compdc1.computing.stu.it-tallaght.ie','studc1.stu.it-tallaght.ie','engdc1.eng.stu.it-tallaght.ie')

        $TextInfo = (Get-Culture).TextInfo

        $ExtensionAttribute15 = 'TUDublin'
        
        $COREconnString = "User id=itt_viewer;Password=""hug67*="" ;Connection Timeout=60;Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=193.1.122.12)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=core22)))"
        $CompDBconnString ="User id=sys; Password=Xy9MEEtj; DBA Privilege=SYSDBA; Connection Timeout=60; Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=10.10.2.7)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=GLOBAL1))); Min Pool Size=10; Connection Lifetime=120; Connection Timeout=60; Incr Pool Size=5; Decr Pool Size=2; Max Pool Size=100; Validate Connection=True"

        # Create tables 
        $UserTable = New-Object System.Data.DataTable 'Results'

        # Define and add the columns
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Domain',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'ADAccount',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'LastLogonDate',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'PasswordExpired',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Office365 Parameters',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Office365 Licence',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Office365 GUID',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'EmailAddress',([String])))
        $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DataRetentionPolicy',([String])))

        $Action = ''
    
        $ActionType = @{
            'NoAction' = @'
No action is necessary at this time.
'@
            'NotRegistered' = @'
According to our records you are not currently registered.

Please contact the Registrars/Part-Time/Finance office and clarify if there is a delay, or if there is something outstanding that they require from you.

An account will be setup automatically once your registration is complete.
'@
            'AccountDisabled' = @'
According to our records there are outstanding issues with your registration.

As a result of this your account has been automatically disabled.

You will need to contact the Registrars/Part Time office to resolve this matter.

Once these issues are resolved, your account will then be enabled again automatically. 

Part time students should contact the Part Time Office:

http://www.it-tallaght.ie/part-time-services


Fulltime students should contact the Finance Department:

+353 1 4042061 or fulltimefees@it-tallaght.ie

If you are still have difficulties with your account following that, please contact us again if you require a password reset etc.
'@
            'NoBirthdate' = @'
According to our records there are outstanding issues with your registration.

A birthdate is not recorded in our systems.

As a result of this your account has been not been setup.

You will need to contact the Registrars/Part Time office to resolve this matter.

Once these issues are resolved, your account will then be setup automatically. 

Part time students should contact the Part Time Office:

http://www.it-tallaght.ie/part-time-services


Fulltime students should contact the Finance Department:

+353 1 4042061 or fulltimefees@it-tallaght.ie


If you are still have difficulties with your account following that, please contact us again if you require a password reset etc.
'@
            'Part-time EL student' = @'
No AD user accounts are created for part-time students who are 'EL' registered.                
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

            $CompDBsqlString = @" 
                            SELECT Username,Account_Status FROM dba_users WHERE username LIKE `'$Id`'
"@
                
            Get-DBResult  $COREconnString $COREsqlString $UserTable
             
            $RegUser = $UserTable.Rows | Where-Object ID -Like $Id
            If ($RegUser) {
                $TUDUser = $RegUser
            }
            Else { 
                $UnRegUser = $UserTable.NewRow()
                $TUDUser = $UnRegUser }

            # Search all student domains till we find the AD user account (assume no duplicates!)
            $DC = 0
            Do {
                $ADUser = Get-ADUser -Filter "SamAccountName -Like '$ID'" -Properties Company,Office,EmailAddress,ExtensionAttribute2,ExtensionAttribute15,ProxyAddresses,LastLogonDate,PasswordExpired,MemberOf,mS-DS-ConsistencyGuid -Server $SearchDCs[$DC]
                $DC = $DC + 1
            } While ($Null -eq $ADUser)

            If ( $Null -eq $ADuser ) { 'User account not created yet'}
            ElseIf ($ADUser) {                       
                $TUDUser.Domain = $SearchDCs[$DC-1].Split('.')[1]
                $TUDUser.ADAccount = $ADUser.SamAccountName
                $TUDUser.LastLogonDate = $ADUser.LastLogonDate
                $TUDUser.PasswordExpired = $ADUser.PasswordExpired

                $CorrectProxyAddresses = @("SMTP:$($ADUser.EmailAddress)", "smtp:$($ADUser.SamAccountName)@myTUDublin.mail.onmicrosoft.com","sip:$($ADUser.EmailAddress)")
                $ProxyTest1 = ($ADUser.ProxyAddresses -contains $CorrectProxyAddresses[0]) -and ($ADUser.ProxyAddresses -contains $CorrectProxyAddresses[1]) -and ($ADUser.ProxyAddresses -contains $CorrectProxyAddresses[2])
                $ProxyTest2 = (($ADUser.ProxyAddresses).Count -eq 4) -and ($ADUser.ProxyAddresses -like 'x500*')
                
                $Office365Test = ($ADUser.EmailAddress -eq "$($ADUser.SamAccountName)@mytudublin.ie") -and ($ADUser.ExtensionAttribute15 -eq $ExtensionAttribute15) -and $ProxyTest1 -and $ProxyTest2
                $TUDUser.'Office365 Parameters' = $Office365Test

                $Office365Licence = $ADUser.MemberOf | Where-Object {($_ -like '*A3*') -or ($_ -like '*A1*')}
                If ($Office365Licence -like '*A3*') { $Office365Licence = 'A3'}
                ElseIf ($Office365Licence -like '*A1*') { $Office365Licence = 'A1'}
                Else {$Office365Licence = 'No'}
                $TUDUser.'Office365 Licence' = $Office365Licence

                If ($Null -ne ($ADUser.'mS-DS-ConsistencyGuid')) { $TUDUser.'Office365 GUID' = 'True' } 
                Else {$TUDUser.'Office365 GUID' = 'False'}

                $TUDUser.EmailAddress = $ADUser.EmailAddress
                
                If ($Null -eq $ADUser.extensionAttribute2){
                    $TUDUser.DataRetentionPolicy = 'N/A'
                }
                ElseIf ($ADUser.extensionAttribute2){
                    $TUDUser.DataRetentionPolicy = $ADUser.extensionAttribute2 
                }        
    #region ComputingDB Account 
                #If Computing, check their DB account
                If ($TUDUser.Domain -eq 'computing'){
                    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount',([String])))
                    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount_Status',([String])))
                    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount_DefaultPwd',([String])))

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
    #endregion                              
            }
        }   
    }
    End {
        If ($RegUser) { 
            $UserTable.Columns['LAST_UPDATE'].ColumnName = 'LAST_UPDATE(CORE)'

            If ($UserTable.Rows[0].Account_Action -eq 'DISABLE') { $Action = $Action + $ActionType.Get_Item('AccountDisabled') }
            If (!$UserTable.Rows[0].PASSWORD -and $UserTable.Rows[0].ID ) { $Action = $Action + $ActionType.Get_Item('NoBirthdate') }
        
            If (!$Action) { $Action = $Action + $ActionType.Get_Item('NoAction') }
        }
        Else { 
            "$ID : Not registered"
            $Action = $Action + $ActionType.Get_Item('NotRegistered')
        }

        $TUDUser

        Write-Output 'Action:'
        Write-Output $Action

        #CopyToClipboard?
        If ($CopyToClipboard -and $Action) { Set-Clipboard $Action }
    }
} # End: Function Get-TUDUser


Function Reset-TUDUser {
    <#
    .Synopsis
    Short description
    .DESCRIPTION
    Long description
    .EXAMPLE
    Reset-ITTUser -Identity
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
        [String[]]$Id,

        # Param2 help description
        [Parameter(Mandatory=$False)]
        [Switch]$CopyToClipboard
    )

    Begin {

    }
    Process {
        If ($PSCmdlet.ShouldProcess("Target", "Operation")){
        }
        "ID is $ID"
    }
    End {
    
    }
} # End: Function Reset-TUDUser


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


Function Set-ODPNetManagedDriver {
    If (!(Test-Path -Path "$env:ProgramFiles\PackageManagement\NuGet\Packages\Oracle.ManagedDataAccess*")) {
        If ($Null -eq (Get-PackageProvider -Name NuGet)) { 
            Install-PackageProvider -Name NuGet -Verbose | Out-Null 
        }
    
        If ($Null -eq (Get-PackageSource -Name NuGet -ErrorAction SilentlyContinue)) { 
            Register-PackageSource -Name NuGet -ProviderName NuGet -Location 'https://www.nuget.org/api/v2/' -Verbose
        }
    
        If ($Null -eq (Get-Package -Name Oracle.ManagedDataAccess -ErrorAction SilentlyContinue)) {
            Find-Package -Name Oracle.ManagedDataAccess -ProviderName NuGet | Install-Package -Scope AllUsers -Force -Verbose
        }
    }  

    # Load the ODP.NET assembly into Powershell 
       Add-Type -Path "$env:ProgramFiles\PackageManagement\NuGet\Packages\Oracle.ManagedDataAccess.$($(Get-Package -Name Oracle.ManagedDataAccess).Version)\lib\net40\Oracle.ManagedDataAccess.dll"   
} # END: Function Set-ODPNetManagedDriver


Function Import-Credential {

} # END: Function Import-Credential


Function Export-Credential {

} # END: Function Export-Credential


Export-ModuleMember -Function Get-LoggedOnUser, Get-TUDUser, Reset-NetworkAdapter, Reset-TUDUser, Export-Credential