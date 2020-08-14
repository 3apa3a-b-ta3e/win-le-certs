#
# This script will download PFX-file from web-server together with encrypted password and encryption key,
# compare with currently installed certificate and apply it to IIS if it`s newer.
#

# Set variables (change to yours)
$PfxUrl = "https://certdeploy-test.s3-eu-west-1.amazonaws.com/certificate.pfx"
$EncfileUrl = "https://certdeploy-test.s3-eu-west-1.amazonaws.com/EncFile.txt"
$PassfileUrl = "https://certdeploy-test.s3-eu-west-1.amazonaws.com/PasswordFile.txt"
$PfxFullPath = "$PSScriptRoot\certificate.pfx"
$EncfileFullPath = "$PSScriptRoot\EncFile.txt"
$PassfileFullPath = "$PSScriptRoot\PasswordFile.txt"
$CertCN = "example.com"
$DaysToExpiration = 30
$LogFile = "$PSScriptRoot\$CertCN-install-log.txt"
$SlackUri = "https://hooks.slack.com/services/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

$CertStore="Cert:\LocalMachine\My"
$expirationDate = (Get-Date).AddDays($DaysToExpiration)
[Net.ServicePointManager]::SecurityProtocol = "TLS12"

# Define how to send messages with Slack
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

# Define how to write log
function WriteLog {
	Param (
	[Parameter(Mandatory=$true)]
	[string] $Message
	)

	"$(Get-Date) - $Message" | Out-File $LogFile -Append -Encoding UTF8
}

# Set password for PFX
$PfxPassword = Get-Content -Path $PassfileFullPath | ConvertTo-SecureString -Key (Get-Content -Path $EncfileFullPath)

try {

# Get current installed certificate for $CertCN and select the latest one
$CertCurrent = (Get-ChildItem -Path $CertStore | Where-Object {$_.Subject -match $CertCN} | Sort-Object -Property NotAfter -Descending | Select-Object -first 1)

# Importing modules
Import-Module WebAdministration

# Get current binded certificates and compare with installed
try {
	$Sites = Get-Website | Where {$_.State -eq "Started"} | ForEach-Object {$_.Name}
	$AllCerts = Get-ChildItem -Path IIS:SSLBindings | Where {$Sites -contains $_.Sites.Value} | ForEach-Object {$_.Thumbprint}
	$CertBinded = Get-ChildItem -Path $CertStore | Where {$AllCerts -contains $_.Thumbprint -and $_.Subject -match $CertCN -and $_.Thumbprint -ne $CertCurrent.Thumbprint}
	if ($CertBinded) {
		 Send-MessageToSlack -SendSubject "Warning!" -SendBody "Latest certificate for $($CertCN) on $($env:ComputerName) is not matched with binded in IIS! It will expire on $($CertBinded.NotAfter), latest - on $($CertCurrent.NotAfter)."
		 
		 # Rebind cert to the latest. If uncomment - change Slack message above.
		 #(Get-WebBinding -Protocol "https" | Where-Object {$_.bindingInformation -match $CertCN}).AddSslCertificate($CertCurrent.Thumbprint, "My")
		}
	} catch {
	Send-MessageToSlack -SendSubject "Error comparing certificates at $($env:ComputerName)" -SendBody "$_.Exception.Message"
}

# Stop if it`s too soon to check
if ( $CertCurrent.NotAfter -lt $expirationDate) { 
	Write-Verbose "Time to check for new certificate!"
	} else {
	Write-Verbose "More than $DaysToExpiration days left to expire, no need to worry."
	Return
	}

# Downloading files from remote location
Invoke-WebRequest -Uri $PfxUrl -OutFile $PfxFullPath
Invoke-WebRequest -Uri $EncfileUrl -OutFile $EncfileFullPath
Invoke-WebRequest -Uri $PassfileUrl -OutFile $PassfileFullPath

# Get the expire date of certificate in downloaded PFX
$CertNew = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$CertNew.Import($PfxFullPath, $PfxPassword)

	} catch {
	WriteLog $_.Exception.Message
	Send-MessageToSlack -SendSubject "Failed to check new certificate at $($env:ComputerName)" -SendBody "$_.Exception.Message"
	Return
}

# Compare expire dates and if downloaded cert is newer - import it into local store
if ( $CertNew.NotAfter -gt $CertCurrent.NotAfter ) {
    
	try {

    # We are using Import-PfxCertificate here and not the .NET function for reason! Don`t even try to save cert using System.Security.Cryptography.X509Certificates.X509Certificate2 - it will fail with completely unrelated error!
    $PfxSecutePassword = $PfxPassword | ConvertTo-SecureString -AsPlainText -Force
    Import-PfxCertificate -Filepath $PfxFullPath -CertStoreLocation $CertStore -Password $PfxSecutePassword

    # Apply new cert to IIS
	(Get-WebBinding -Protocol "https" | Where-Object {$_.bindingInformation -match $CertCN}).AddSslCertificate($CertNew.Thumbprint, "My")
            	
	# Write success message to log
    WriteLog "New certificate for $CertCN imported and applied successfully."
    Send-MessageToSlack -SendSubject "New cert at $($env:ComputerName)" -SendBody "Certificate for $CertCN imported and applied successfully."
	} catch {
	WriteLog $_.Exception.Message
	Send-MessageToSlack -SendSubject "Failed to apply new certificate at $($env:ComputerName)" -SendBody "$_.Exception.Message"
		}
    }
else  {
    # Do nothing (except logging) in case the newer cert is no newer than currently installed
    WriteLog "No new certificate for $CertCN"
	}

# Remove downloaded files
if (Test-Path $PfxFullPath) {Remove-Item $PfxFullPath}
if (Test-Path $EncfileFullPath) {Remove-Item $EncfileFullPath}
if (Test-Path $PassfileFullPath) {Remove-Item $PassfileFullPath}
