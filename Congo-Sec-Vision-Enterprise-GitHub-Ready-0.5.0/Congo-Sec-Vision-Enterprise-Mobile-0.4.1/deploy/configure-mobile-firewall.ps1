[CmdletBinding()]
param(
  [string]$LabSubnet = "10.2.2.0/24",
  [string]$MobileTrustedSubnet = "10.188.0.0/16"
)
$ErrorActionPreference = "Stop"
$profiles = Get-NetFirewallProfile
if (@($profiles | Where-Object Enabled).Count -eq 0) { throw "Le pare-feu Windows est désactivé." }
# L'API directe reste limitée au réseau VMware des machines de laboratoire.
Get-NetFirewallRule -DisplayName "Congo Sec Vision API Lab" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "Congo Sec Vision API Lab" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8081 -RemoteAddress $LabSubnet -Profile Any -Description "API SOC réservée au segment VMware de laboratoire."
# Ports HTTPS/ACME limités au réseau mobile de confiance pour un accès LAN uniquement.
# Pour un accès depuis Internet, configurer une publication sur le routeur et une règle adaptée après validation.
Get-NetFirewallRule -DisplayName "Congo Sec Vision HTTPS Mobile" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "Congo Sec Vision HTTPS Mobile" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80,443 -RemoteAddress $MobileTrustedSubnet -Profile Any -Description "Reverse proxy HTTPS accessible depuis le sous-réseau mobile autorisé."
Write-Host "Règles créées. API : $LabSubnet ; HTTPS : $MobileTrustedSubnet" -ForegroundColor Green
Write-Warning "Adapte MobileTrustedSubnet à ton vrai réseau Wi-Fi. N'ouvre pas 80/443 à tout Internet sans configuration réseau et durcissement appropriés."
