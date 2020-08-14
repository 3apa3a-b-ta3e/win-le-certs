#
# This script will check for any binded to IIS certificates and send message to Slack if found any that about to expire.
#

$DaysToExpiration = 30
$SlackUri = "https://hooks.slack.com/services/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Send-MessageToSlack {
	Param (
	[Parameter(Mandatory=$true)]
	[string] $SendSubject,

	[Parameter(Mandatory=$true)]
        [string] $SendBody
	)
 
	$body = ConvertTo-Json @{
		pretext = "$SendSubject"
		text = "$SendBody"
    }
	
	Invoke-RestMethod -Uri $SlackUri -Method Post -Body $body -ContentType 'application/json' | Out-Null
}

$expirationDate = (Get-Date).AddDays($DaysToExpiration)

try {
	Import-Module WebAdministration
	$Sites = Get-Website | Where {$_.State -eq "Started"} | ForEach-Object {$_.Name}
	$AllCerts = Get-ChildItem IIS:SSLBindings | Where {$Sites -contains $_.Sites.Value} | ForEach-Object {$_.Thumbprint}
	$Cert = Get-ChildItem "Cert:\LocalMachine\My" | Where {$AllCerts -contains $_.Thumbprint -and $_.NotAfter -lt $expirationDate}
	if ($Cert) {
		 Send-MessageToSlack -SendSubject "Found expiring certificate on $env:ComputerName!" -SendBody "$($Cert.Subject) will expire on $($Cert.NotAfter)"
		}
	} catch {
	Send-MessageToSlack -SendSubject "List expiring certs failed at $env:ComputerName" -SendBody "$_.Exception.Message"
}
