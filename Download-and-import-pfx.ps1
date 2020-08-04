# Set variables 
$PfxUrl = "https://some.site.net/cert/certificate.pfx"
$PfxFullPath = "C:\Cmd\certificate.pfx"
[Net.ServicePointManager]::SecurityProtocol = "TLS12"
$PfxPassword = "sUpeRseCUrepaSSw0rd!"
$PfxImportSettings = "Exportable,PersistKeySet"
$CertCN = "example.com"
$LogFile = "C:\Cmd\cert-log.txt"

# Downloading certificate from remote location
Invoke-WebRequest -Uri $PfxUrl -OutFile $PfxFullPath

# Get the expire date of current installed certificate
$CertCurrent = (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Subject -match $CertCN} | Sort-Object -Property NotAfter -Descending | Select-Object -first 1)

# Get the expire date of certificate in downloaded PFX
$CertNew = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$CertNew.Import($PfxFullPath, $PfxPassword, $PfxImportSettings)

$Date = (Get-Date).DateTime

# Compare expire dates and if downloaded cert is newer - import it into local store
if ( $CertNew.NotAfter -gt $CertCurrent.NotAfter ) {
    
    # We are using Import-PfxCertificate here and not the .NET function for reason! Don`t even try to save cert using System.Security.Cryptography.X509Certificates.X509Certificate2 - it will fail with completely unrelated error!
    $PfxSecutePassword = $PfxPassword |ConvertTo-SecureString -AsPlainText -Force
    Import-PfxCertificate -Exportable -Filepath $PfxFullPath -CertStoreLocation cert:\LocalMachine\My -Password $PfxSecutePassword

    # Importing modules
    Import-Module RemoteDesktopServices
    Import-Module WebAdministration

    # Apply new cert to IIS (note to self - get rid of hardcoded port 443)
    (Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 | Where-Object {$_.sslFlags -match 0}).AddSslCertificate($CertNew.Thumbprint, "My")

    # Apply new certificate to RD Gateway
    Set-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint -Value $CertNew.Thumbprint

    # Apply new certificate to RDP
    $WmiPath = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
    Set-WmiInstance -Path $WmiPath -argument @{SSLCertificateSHA1Hash=$CertNew.Thumbprint}

    # Remove downloaded PFX
    Remove-Item $PfxFullPath
    
    # Write success message to log (note to self - replace this carp with more mature logging function)
    $updated = "New certificate imported and applied"
    $output = $date + " - " + $updated
    Write-Output $output | Out-File $LogFile -NoClobber -Append
    Start-Sleep -s 2
    exit
    }
else  {
    
    # Do nothing (except logging) in case the newer cert is no newer than currently installed
    Remove-Item $PfxFullPath
    $updated = "No new certificate found, exiting"
    $output = $date + " - " + $updated
    Write-Output $output | Out-File $LogFile -NoClobber -Append
    Start-Sleep -s 2
    exit
    }
