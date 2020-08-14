#
# This script will renew any Let`sEncrypt certificate issued with help of Posh-ACME module (yes, this module must be installed).
#

# Set required variables
$env:POSHACME_HOME = 'C:\Posh-ACME'
$SendFrom = "server@example.com"
$SendTo = "admin@example.com"
$SendgridAPIkey = "Sendgrid api key here"
$LogFile = "$env:POSHACME_HOME\RenewLog.txt"
$CurrentCertName = (Get-PACertificate).AllSANs|select-object -first 1

# Re-import Posh-ACME module with correct HOME settings
Import-Module Posh-ACME -Force

# Only continue if less than 29 days to cerificate expiration
if ((Get-Date).AddDays(29).Date -gt (Get-PACertificate).NotAfter.Date) {
	Write "Time to renew"
 } else {
	Write "Too early to renew"
	Return
}

# Define how to write log
function WriteLog {
	Param (
	[Parameter(Mandatory=$true)]
	[string]$Message
	)

	"$(Get-Date) - $Message" | Out-File $LogFile -Append -Encoding UTF8
}

# Define how to send message
function Send-EmailWithSendGrid {
	Param (
	[Parameter(Mandatory=$true)]
	[string] $SendSubject,

	[Parameter(Mandatory=$true)]
        [string] $SendBody
	)
 
		$Headers = @{}
		$Headers.Add("Authorization","Bearer $SendgridAPIkey")
		$Headers.Add("Content-Type", "application/json")

		$jsonRequest = [ordered]@{
			personalizations= @(@{to = @(@{email =  "$SendTo"})
			subject = "$SendSubJect" })
			from = @{email = "$SendFrom"}
			content = @( @{ type = "text/plain"
			value = "$SendBody" }
		)} | ConvertTo-Json -Depth 10

	Invoke-RestMethod -Uri "https://api.sendgrid.com/v3/mail/send" -Method Post -Headers $Headers -Body $jsonRequest 
}

# Try to renew cert and log/send the result
try {
	Submit-Renewal -WarningAction Stop -ErrorAction Stop -Verbose
	$NewCertThumbprint = (Get-PACertificate).Thumbprint
	WriteLog "Renew successful for $CurrentCertName"
 } catch {
	WriteLog $_.Exception.Message
	Send-EmailWithSendGrid -SendSubject "Renew failed for $CurrentCertName" -SendBody "$_.Exception.Message"
	Return
}

# Continue on success, import modules
Import-Module RemoteDesktopServices
Import-Module WebAdministration

# Try to apply new certificate to IIS, RDP and RDGW
try {
	# Apply to all IIS sites with https enabled
	(Get-WebBinding -Protocol "https").AddSslCertificate($NewCertThumbprint, "My")
	
	# Apply to Remote Desktop Gateway (RDP over HTTPS)
	Set-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint -Value $NewCertThumbprint -ErrorAction Stop
	
	# Apply to regular RDP (default binding)
	$WmiPath = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
	Set-WmiInstance -Path $WmiPath -argument @{SSLCertificateSHA1Hash=$NewCertThumbprint} -ErrorAction Stop
	
	# Apply to Web Management service and WebDeploy as well
	$webManagementService = Get-Service WMSVC -ErrorAction Stop
	if ($webManagementService.Status -eq "Running") {
		Stop-Service WMSVC -ErrorAction Stop
	}
	
	$webManagementPort = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "Port").Port
	$webManagementIP = (Get-ChildItem -Path IIS:\SslBindings | Where-Object Port -eq $webManagementPort).IPAddress.IPAddressToString
	Get-ChildItem -Path IIS:\SslBindings | Where-Object Port -eq $webManagementPort | Where-Object IPAddress -eq $webManagementIP | Remove-Item -ErrorAction Stop
	Get-Item -Path Cert:\LocalMachine\My\$NewCertThumbprint | New-Item -Path IIS:\SslBindings\$webManagementIP!$webManagementPort -ErrorAction Stop

        $bytes = for($i = 0; $i -lt $NewCertThumbprint.Length; $i += 2) { [convert]::ToByte($NewCertThumbprint.SubString($i, 2), 16) }
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name SslCertificateHash -Value $bytes -ErrorAction Stop

	Start-Service WMSVC -ErrorAction Stop	
	
	# Write log and send email on success
	WriteLog "Renew and apply successful for $CurrentCertName"
	Send-EmailWithSendGrid -SendSubject "Renew and apply successful for $CurrentCertName" -SendBody "Nothing to fix, everything is fine."
 } catch {
	WriteLog $_.Exception.Message
	Send-EmailWithSendGrid -SendSubject "Apply failed for $CurrentCertName" -SendBody "$_.Exception.Message"
}

# Cleanup expired certificates
$AllMyCerts = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse
	Foreach($Cert in $AllMyCerts) {
	if($Cert.NotAfter -lt (Get-Date)) { $Cert | Remove-Item }
 }
