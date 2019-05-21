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

	[OutputType([pscustomobject])]
	[CmdletBinding()]
	Param (
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string[]]$ComputerName = $env:COMPUTERNAME
        
	)
	Begin {
		$ErrorActionPreference = 'Stop'
	}
	Process {
		Try {
			foreach ($comp in $ComputerName)
			{
				$output = @{ 
					ComputerName = $comp 
					UserName = 'Unknown'
					ComputerStatus = 'Offline'
				}
				if (Test-Connection -ComputerName $comp -Count 1 -Quiet) {
					$output.UserName = (Get-CimInstance -Class win32_computersystem -ComputerName $comp).UserName
					$output.ComputerStatus = 'Online'
				}
				[pscustomobject]$output
			}
		}
		catch
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}
}


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
        Example of how to use this cmdlet
    .EXAMPLE
        Another example of how to use this cmdlet
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
    
            # 
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
    
    $password = ConvertTo-SecureString “qazX989%” -AsPlainText -Force
    
                $Cred = New-Object System.Management.Automation.PSCredential (“lab150-lect\administrator”, $password)
    
                $Date = (Get-Date).AddDays(-($Days))
        }
        Process {
            ForEach ($Computer in $ComputerName) {
                $Logon = Get-WinEvent -FilterHashtable @{logname='security';id=4624;data=$UserName} -ComputerName $Computer -Credential $Cred -ErrorAction SilentlyContinue |
                   
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
    
                
                $AccountLogoff = Get-WinEvent -FilterHashtable @{logname='security';id=4634} -ComputerName $Computer -Credential $Cred -ErrorAction SilentlyContinue |  
                
                  Where-Object { ($_.Properties[0].Value -like 'S-1-5-21-*') -and ($_.TimeCreated -gt $Date) } |
    
                    Select-Object -Property TimeCreated,
                        @{label='UserName';expression={$_.properties[1].value}},
                        @{label='LogonType';expression={$_.properties[4].value}},
                        @{label='LogonID';expression={$_.properties[3].value}},
                        @{label='Domain';expression={$_.properties[2].value}},
                        @{label='Event';expression={"AccountLogoff"}}
    
    
                $UserInitiatedLogoff = Get-WinEvent -FilterHashtable @{logname='security';id=4647} -ComputerName $Computer -Credential $Cred -ErrorAction SilentlyContinue |
    
                    Where-Object { ($_.Properties[0].Value -like 'S-1-5-21-*') -and ($_.TimeCreated -gt $Date) } |
    
                    Select-Object -Property TimeCreated,
                        @{label='UserName';expression={$_.properties[1].value}},
                        @{label='LogonID';expression={$_.properties[3].value}},
                        @{label='Domain';expression={$_.properties[2].value}},
                        @{label='Event';expression={"UserInitiatedLogoff"}}
                }
        }
        End {
                $Logs = $Logon + $AccountLogoff + $UserInitiatedLogoff
    
                $Logs| ForEach-Object {
                    If ($_.LogonType -eq '2') { $_.LogonType = 'Interactive' }
                    ElseIf ($_.LogonType -eq '3') { $_.LogonType = 'Network' }
                    ElseIf ($_.LogonType -eq '7')  { $_.LogonType = 'Unlock' }
                    ElseIf ($_.LogonType -eq '10')  { $_.LogonType = 'RemoteInteractive' }
                    ElseIf ($_.LogonType -eq '11')  { $_.LogonType = 'CachedInteractive' }
                    }
                
                $Logs
        }
    }


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
    Param
    (
        # A list or an array of type string
        [Parameter(Mandatory=$True,
                   ValueFromPipeline=$True)]
        [String[]]$LabName 
    )
   
    Begin   
    { $IPType = "IPv4" 
      Write-Verbose "Checking computer name..."
    }
      
    Process 
    { 
        ForEach ($Lab in $LabName) { 
        If ($env:COMPUTERNAME -like "$Lab*") { 
                                                    Write-Verbose "Matched lab $Lab, check dhcp and enable if required"
                                                    
                                                    # Enabling the physical adapter if it is 'DISABLED' to determine if it is 'DISCONNECTED' or 'UP'
                                                    Get-NetAdapter -Physical | where Status -Eq 'Disabled' | Enable-NetAdapter
       
                                                    $AdapterUp = Get-NetAdapter -Physical | Where Status -eq "Up" # 'Up' means NIC 'CONNECTED' and adapter 'ENABLED'

                                                    If ($AdapterUp) { 
                                                                    # If the adapter name was changed, rename it to 'Ethernet'
                                                                    If ($AdapterUp.Name -ne 'Ethernet') { $AdapterUp | Rename-NetAdapter -NewName 'Ethernet' -Confirm:$false
                                                                                                          $AdapterUp.Name = 'Ethernet'
                                                                                                        } # EndIf ($AdapterUp.Name -ne 'Ethernet')

                                                                    $Interface = $AdapterUp | Get-NetIPInterface -AddressFamily $IPType

                                                                    If (!$Interface.Dhcp) {
                                                                                        Write-Verbose "DHCP disabled"
                                                                                        # Remove existing static gateway if it exists
                                                                                        If (($Interface | Get-NetIPConfiguration).Ipv4DefaultGateway) { $Interface | Remove-NetRoute -Confirm:$false }                                                                     

                                                                                        # Enable DHCP
                                                                                        Write-Verbose "Setting DHCP on..."
                                                                                        $Interface | Set-NetIPInterface -DHCP Enabled -Verbose -Confirm:$false

                                                                                        # Configure the  DNS Servers automatically
                                                                                        Write-Verbose "Setting DNS to automatic via DHCP"
                                                                                        $Interface | Set-DnsClientServerAddress -ResetServerAddresses -Verbose -Confirm:$false

                                                                                        # Set WINS statically
                                                                                        Netsh interface ip set winsservers name=$($Adapter.name) static 193.1.120.4
                                                  
                                                                                        # Restart the network adapter
                                                                                        Write-Verbose "Restarting network adapter $($Adapter.Name)"
                                                                                        $Adapter | Disable-NetAdapter -Verbose -Confirm:$false
                                                                                        Start-Sleep -s 5
                                                                                        $Adapter | Enable-NetAdapter -Verbose -Confirm:$false
                                                                                        Write-Verbose "Network adapter reset complete"
                                                                                            } # EndIf (!$Interface.Dhcp)                                                         
                                                                    Else { Write-Verbose "DHCP already enabled"}
                                                                    
                                                                    } # EndIf ($AdapterUp)                                                                   
                                                    Else { Write-Verbose "Network cable not connected, leaving as is" }
                                                                                      
        } # EndIf ($env:COMPUTERNAME -like "$ComputerName*")
        Else { Write-Verbose "Not matching network lab $Lab, leaving network adapter unchanged" }  
                                  }                 
    }  
} # End: Function Reset-NetworkAdapter


Function Get-TUDUser {
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Get-ITTUser -Identity
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

        # Param2 help description
        [Parameter(Mandatory=$False)]
        [Switch]$Home,

        # Param3 help description
        [Parameter(Mandatory=$False)]
        [Switch]$CopyToClipboard
    )

    Begin {
    Write-Output 'ToDo: Need an enabled core erasmus student account so as to tabulate results of multiple AD accounts properly.'
    Write-Output 'ToDo: Need to have $Identity as an output to pipe into Reset-ITTUser.'

    Set-ODPNetManagedDriver

    $Domain = (Get-ADForest).Domains

    $TextInfo = (Get-Culture).TextInfo

    $HomeFolderQuota = 4
       
    $COREconnString = "User id=itt_viewer;Password=""hug67*="" ;Connection Timeout=60;Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=193.1.122.12)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=core22)))"
    $CompDBconnString ="User id=sys; Password=Xy9MEEtj; DBA Privilege=SYSDBA; Connection Timeout=60; Data Source=(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=10.10.2.7)(PORT=1521)))(CONNECT_DATA=(SERVICE_NAME=GLOBAL1))); Min Pool Size=10; Connection Lifetime=120; Connection Timeout=60; Incr Pool Size=5; Decr Pool Size=2; Max Pool Size=100; Validate Connection=True"

    # Create tables 
    $UserTable = New-Object System.Data.DataTable “Results”
    $CompDBUserTable = New-Object System.Data.DataTable “CompDB Results”
    
    # Define and add the columns
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'ValidUser',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'Duplicate',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'ADAccount',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'LastLogonDate',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'PasswordExpired',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'EmailAddress',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DataRetentionPolicy',([String])))

    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'HomeFolder',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'HomeFolderPermissions',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'HomeFolderUsage',([String])))

    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount_Status',([String])))
    $UserTable.Columns.Add((New-Object System.Data.DataColumn 'DBAccount_DefaultPwd',([String])))

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
                'Duplicate' = @'
You have a previous user account in another School/Department which needs to be deleted. 

We have requested this happen as soon as possible. (to be coded!)

Once this is done, you will be able to login to Moodle successfully.                
'@
                'HomeFolderFull' = @'
The home folder associated with your student account is full or nearly full. 

There is a quota applying to your account.

Please consider either of the following:
(1) Delete files that you no longer wish to keep
(2) You alternative storage, e.g. Microsoft Office 365 (1TB storage)
            
            https://login.microsoftonline.com               
'@
                'HomeFolderPermissions' = @'
The home folder associated with your student account had permission errors.
We have fixed these errors so that your home folder and files should be accessible again.              
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
                 
					WHERE ID LIKE '$Id%'                    
"@

            $CompDBsqlString = @" 
                                SELECT Username,Account_Status FROM dba_users WHERE username LIKE `'$Id`%`'
"@
            
            Get-DBResult  $COREconnString $COREsqlString $UserTable
            
            $RegUser = $UserTable.Rows | Where-Object ID -Like $ID*
            If ($RegUser) { 
       
                $FoundDomain = New-Object System.Collections.Generic.List[System.Object]
                $DomADAccount = New-Object System.Collections.Generic.List[System.Object]
                $DomLastLogonDate = New-Object System.Collections.Generic.List[System.Object]
                $DomPasswordExpired = New-Object System.Collections.Generic.List[System.Object]
                $DomEmailAddress = New-Object System.Collections.Generic.List[System.Object]
                $DomDataRetentionPolicy = New-Object System.Collections.Generic.List[System.Object]

                ForEach ($Dom in $Domain) { 
                    $ADUser = Get-ADUser -Filter "SamAccountName -Like '$ID*'" -Properties * -Server $Dom
                    
                    If ($ADUser) { 
                        $FoundDomain.Add($Dom.Split('.')[0])
                        $DomADAccount.Add($ADUser.SamAccountName)
                        $DomLastLogonDate.Add($ADUser.LastLogonDate)
                        $DomPasswordExpired.Add($ADUser.PasswordExpired)
                        $DomEmailAddress.Add($ADUser.EmailAddress)
                        $DomDataRetentionPolicy.Add($ADUser.extensionAttribute2)
                        
                        If ( $FoundDomain | Group-Object | Where-Object Count -gt 1) { 
                            $RegUser.Duplicate = $FoundDomain        
                            $Action = $Action + $ActionType.Get_Item('Duplicate')
                        }
                        Else { $RegUser.Duplicate = 'No'}
                    }  
                }

                If ($FoundDomain -eq $Null) { 'User account not created yet'}
                 
                # This doesn't work below as the last domain queried comes back blank
                $RegUser.ADAccount = $DomADAccount
                $RegUser.LastLogonDate = $DomLastLogonDate
                $RegUser.PasswordExpired = $DomPasswordExpired
                $RegUser.EmailAddress = $DomEmailAddress
                $RegUser.DataRetentionPolicy = $DomDataRetentionPolicy
                            
#region ComputingDB Account 
                            #If Computing, check their DB account
                            Get-DBResult  $CompDBconnString $CompDBsqlString $CompDBUserTable
                           
                            If ($CompDBUserTable.Username) { 
                                                             $RegUser.DBAccount = $CompDBUserTable.Username
                                                             $RegUser.DBAccount_Status = $CompDBUserTable.Account_Status
                                                             $RegUser.DBAccount_DefaultPwd = "db$($Reguser.Password)"

                                                             $CompDBUserTable.Clear()
                                                           }

                            Else { $CompDBUserTable
                                   $RegUser.DBAccount = 'N/A'
                                   $RegUser.DBAccount_Status = 'N/A'
                                   $RegUser.DBAccount_DefaultPwd = 'N/A'
                                 }
#endregion

#region Home Directory
                            If ($Home) {
                                        Switch -wildcard ($($RegUser.Programme)) {  
                                                                                   "TA_K*" { $HomeServer ='comphome' }
                                                                                   "TA_S*" { $HomeServer = 'scisan' }                                                                 
                                                                                   "TA_ERA*" { $HomeServer ='comphome' }
                                                                                   "TA_BDAMKT*" { $HomeServer ='comphome' }
                                                                                  }
                                        $HomePath = "\\$HomeServer\HomeDir$\$($RegUser.ADAccount)"
                                        If (Test-Path $HomePath -PathType Container) {
                                                                                        $RegUser.HomeFolder = $HomePath
                                                                                        $Usage =  [math]::Round($(Get-ChildItem $HomePath -Recurse | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum /1gb, 2)
                                                                                        $RegUser.HomeFolderUsage = "$Usage"+ 'GB'

                                                                                        # Check home folder ownership 
                                                                                        $HomeFolderOwner = (Get-Acl $HomePath).Owner
                                                                                        $NetBiosName = (Get-ADDomain (($RegUserAD.DistinguishedName.Split(",") | Where-Object {$_ -Like "DC=*"})  -Join ",")).NetBiosName
                                                                                        # What if more than one domain in ValidUser?
                                                                                        $NetBiosUser = "$NetBiosName\$($RegUser.ADAccount)"
                                                                                        If ( $HomeFolderOwner -NE $NetBiosUser) { $RegUser.HomeFolderPermissions = "Error in ownership permissions: Owner is $HomeFolderOwner" }
                                                                                                                                                                                               
                                                                                        Else { $RegUser.HomeFolderPermissions = 'Ok' }
                                                                                                              }
                                        Else { $RegUser.HomeFolder = "HomeFolder missing on \\$HomeServer\HomeDir$" }    
                                        }
                            Else { $RegUser.HomeFolder = "Not requested. Use -Home switch for details" }
                               
#endregion                               
                                                         
                       }
            Else { "$ID : Not registered"
                   $Action = $Action + $ActionType.Get_Item('NotRegistered')}

         }   
    }
    End {
    $UserTable.Columns['LAST_UPDATE'].ColumnName = 'LAST_UPDATE(CORE)'

    If ($UserTable.Rows[0].Account_Action -eq 'DISABLE') { $Action = $Action + $ActionType.Get_Item('AccountDisabled') }
    If (!$UserTable.Rows[0].PASSWORD -and $UserTable.Rows[0].ID ) { $Action = $Action + $ActionType.Get_Item('NoBirthdate') }
    If ($Usage -eq $HomeFolderQuota) { $Action = $Action + $ActionType.Get_Item('HomeFolderFull') }
    If ($RegUser.HomeFolderPermissions -ne 'OK' -and $UserTable.Rows[0].ID -and $HomePath) { $Action = $Action + "`n`n" + $ActionType.Get_Item('HomeFolderPermissions') }

    If (!$Action) { $Action = $Action + $ActionType.Get_Item('NoAction') }

    $UserTable

    Write-Output 'Action:'
    Write-Output $Action

#region CopyToClipboard
                            If ($CopyToClipboard -and $Action) { Set-Clipboard $Action }
#endregion
    
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

        [Parameter(Mandatory=$true)]

        [ValidateScript({$_ -match '\bdata source\b'})]

        [string]$connString,

 

        [ValidateScript({$_ -match '\bselect\b'})]

        [Parameter(Mandatory=$true)]

        [string]$sqlString,


        [Parameter(Mandatory=$True)]

        [System.Data.DataTable]$DataTable

    )


    Try {

        $conn = New-Object Oracle.ManagedDataAccess.Client.OracleConnection($connString)

        $cmd=$conn.CreateCommand()

        $cmd.CommandText= $sqlString
 
        $da = New-Object Oracle.ManagedDataAccess.Client.OracleDataAdapter($cmd)

        # Fill() method will “open” and “close” the database connection as part of its normal operation
        $da.fill($DataTable) | Out-Null
             

    } Catch {

        Write-Error ("Can't open connection: {0}`n{1}" -f `

        $conn.ConnectionString, $_.Exception.ToString())

    } Finally {

        # Cleanup
        If ($conn.State -eq 'Open') { $cmd.Dispose()
                                      $conn.Close() }
    }

    
} # END: Function Get-DBResult


Function Test-Verbose {
[CmdletBinding()]
Param()
	[System.Management.Automation.ActionPreference]::SilentlyContinue -ne $VerbosePreference
} # END: Function Test-Verbose


Function Set-ODPNetManagedDriver {
    
    # Load the ODP.NET assembly into Powershell 
    Add-Type -Path “C:\ODP_NET_Managed121012\odp.net\managed\common\Oracle.ManagedDataAccess.dll"

} # END: Function Set-ODPNetManagedDriver


Export-ModuleMember -Function Get-LoggedOnUser, Get-TUDUser, Get-UserSecurityLog, Reset-NetworkAdapter, Reset-TUDUser