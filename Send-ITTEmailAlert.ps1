<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>Function Send-ITTEmailAlert {
Param(
[String] $SupportEmailAddress,
[String] $MailingServer,
[String] $EmailSubject,
[String] $EmailBody,
[String] $SmtpServer,
[String] $EmailCc)

Send-MailMessage -To $SupportEmailAddress -From $MailingServer `
-Subject $EmailSubject -Body $EmailBody -SmtpServer $SmtpServer -Cc $EmailCc -Priority High

}