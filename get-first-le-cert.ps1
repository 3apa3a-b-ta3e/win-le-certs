Install-Module -Name Posh-ACME -Scope AllUsers
$env:POSHACME_HOME = 'c:\Posh-ACME'
Import-Module Posh-ACME -Force

Set-PAServer LE_PROD

$pArgs = @{ CFTokenInsecure = 'xxxxxxxxxx' }
$pArgs.CFTokenReadAllInsecure = 'yyyyyyyyyy'

New-PACertificate 'example.com','*.example.com' -AcceptTOS -Contact admin@example.com -DnsPlugin Cloudflare -PluginArgs $pArgs -CertKeyLength ec-256 -NewCertKey -FriendlyName "ACME-Poch generated" -Install -PfxPass "vEryseCretpaSSworD!" -Verbose