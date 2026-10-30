# Run from a domain admin workstation with RSAT Group Policy tools.
# Usage: .\Install-CongoSecVision-GPO.ps1 -DomainFqdn corp.example -ServerUrl https://soc.example.com -EnrollmentToken <scoped-token> -TargetOU "OU=Workstations,DC=corp,DC=example"
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$DomainFqdn,
 [Parameter(Mandatory=$true)][string]$ServerUrl,
 [Parameter(Mandatory=$true)][string]$EnrollmentToken,
 [Parameter(Mandatory=$true)][string]$TargetOU,
 [string]$GpoName="Congo Sec Vision - Endpoint Agent"
)
$ErrorActionPreference="Stop"
Import-Module GroupPolicy
Import-Module ActiveDirectory
$domain=Get-ADDomain -Identity $DomainFqdn
$gpo=Get-GPO -Name $GpoName -Domain $DomainFqdn -ErrorAction SilentlyContinue
if(-not $gpo){$gpo=New-GPO -Name $GpoName -Domain $DomainFqdn}
$sysvol="\\$($domain.PDCEmulator)\SYSVOL\$DomainFqdn\scripts\CongoSecVision"
New-Item -ItemType Directory -Force -Path $sysvol | Out-Null
$source=Join-Path $PSScriptRoot "..\.."
Copy-Item (Join-Path $source "agent\agent.py") $sysvol -Force
Copy-Item (Join-Path $source "agent\requirements.txt") $sysvol -Force
Copy-Item (Join-Path $PSScriptRoot "gpo-startup.ps1") $sysvol -Force
Set-Content (Join-Path $sysvol "server.txt") $ServerUrl -NoNewline
Set-Content (Join-Path $sysvol "enrollment-token.txt") $EnrollmentToken -NoNewline
# GPO startup script uses the local PowerShell script path in SYSVOL.
Set-GPStartupScript -Name $GpoName -Domain $DomainFqdn -ScriptName "CongoSecVision\gpo-startup.ps1" -ScriptParameters ""
New-GPLink -Name $GpoName -Target $TargetOU -Domain $DomainFqdn -LinkEnabled Yes
Write-Warning "SYSVOL is readable by authenticated domain users. Treat enrollment-token.txt as a shared bootstrap secret: use a narrowly scoped, rotated token and review SYSVOL ACLs before production rollout."
Write-Host "GPO '$GpoName' linked to $TargetOU. Run gpupdate /force or wait for policy refresh." -ForegroundColor Green
