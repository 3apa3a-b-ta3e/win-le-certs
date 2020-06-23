Import-Module RemoteDesktopServices
Import-Module WebAdministration

$PfxFullPath = "C:\cygwin64\home\Administrator\.acme.sh\example.com_ecc\example.com.pfx"
$PfxPassword = "veRYsecRETpaSSword!"
$PfxImportSettings = "Exportable,PersistKeySet"
$CertCN = "example.com"
$LogFile = "C:\Script\cert-log.txt"

$CertCurrent = (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Subject -match $CertCN} | Sort-Object -Property NotAfter -Descending | Select-Object -first 1)

$CertNew = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$CertNew.Import($PfxFullPath, $PfxPassword, $PfxImportSettings)

$Date = (Get-Date).DateTime

if ( $CertNew.NotAfter -gt $CertCurrent.NotAfter ) {

    $PfxSecutePassword = $PfxPassword |ConvertTo-SecureString -AsPlainText -Force
    Import-PfxCertificate -Exportable -Filepath $PfxFullPath -CertStoreLocation cert:\LocalMachine\My -Password $PfxSecutePassword

    (Get-WebBinding -Name "Default Web Site" -Protocol "https").AddSslCertificate($CertNew.Thumbprint, "My")

    Set-Item -Path RDS:\GatewayServer\SSLCertificate\Thumbprint -Value $CertNew.Thumbprint

    $WmiPath = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").__path
    Set-WmiInstance -Path $WmiPath -argument @{SSLCertificateSHA1Hash=$CertNew.Thumbprint}

    $updated = "New certificate imported and applied"
    $output = $date + " - " + $updated
    Write-Output $output | Out-File $LogFile -NoClobber -Append
    Start-Sleep -s 2
    exit
    }
else  {
    $updated = "No new certificate found, exiting"
    $output = $date + " - " + $updated
    Write-Output $output | Out-File $LogFile -NoClobber -Append
    Start-Sleep -s 2
    exit
    }
