Import-Module RemoteDesktopServices
Import-Module WebAdministration

$PfxUrl = "https://some.site.net/cert/certificate.pfx"
$PfxFullPath = "C:\Cmd\certificate.pfx"

[Net.ServicePointManager]::SecurityProtocol = 'TLS12'

Invoke-WebRequest -Uri $PfxUrl -OutFile $PfxFullPath

$PfxPassword = "sUpeRseCUrepaSSw0rd!"
$PfxImportSettings = "Exportable,PersistKeySet"
$CertCN = "CN=company.net"
$LogFile = "C:\Cmd\cert-log.txt"

$CertCurrent = (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Subject -eq $CertCN} | Sort-Object -Property NotAfter -Descending | Select-Object -first 1)

$CertNew = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$CertNew.Import($PfxFullPath, $PfxPassword, $PfxImportSettings)

$Date = (Get-Date).DateTime

if ( $CertNew.NotAfter -gt $CertCurrent.NotAfter ) {

    $PfxSecutePassword = $PfxPassword |ConvertTo-SecureString -AsPlainText -Force
    Import-PfxCertificate -Exportable -Filepath $PfxFullPath -CertStoreLocation cert:\LocalMachine\My -Password $PfxSecutePassword

    (Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 | Where-Object {$_.sslFlags -match 0}).AddSslCertificate($CertNew.Thumbprint, "My")

    Set-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint -Value $CertNew.Thumbprint

    # Commented out setting RDP certificate
    # $WmiPath = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
    # Set-WmiInstance -Path $WmiPath -argument @{SSLCertificateSHA1Hash=$CertNew.Thumbprint}

    Remove-Item $PfxFullPath
    $updated = "New certificate imported and applied"
    $output = $date + " - " + $updated
    Write-Output $output | Out-File $LogFile -NoClobber -Append
    Start-Sleep -s 2
    exit
    }
else  {
    Remove-Item $PfxFullPath
    $updated = "No new certificate found, exiting"
    $output = $date + " - " + $updated
    Write-Output $output | Out-File $LogFile -NoClobber -Append
    Start-Sleep -s 2
    exit
    }
