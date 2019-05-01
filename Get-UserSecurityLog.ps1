

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
