[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:8081",
    [string]$VBoxManagePath = ""
)

$ErrorActionPreference = "Stop"

if (-not $VBoxManagePath) {
    $command = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if (-not $command) { $command = Get-Command VBoxManage -ErrorAction SilentlyContinue }
    if (-not $command) {
        throw "VBoxManage introuvable. Installe VirtualBox ou passe -VBoxManagePath avec le chemin de VBoxManage.exe."
    }
    $VBoxManagePath = $command.Source
}

$secureToken = Read-Host "CSV_VBOX_COLLECTOR_TOKEN (saisi masqué)" -AsSecureString
$tokenPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
    $collectorToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPtr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPtr)
}

if ([string]::IsNullOrWhiteSpace($collectorToken)) {
    throw "Le jeton du collecteur est obligatoire."
}

$raw = & $VBoxManagePath list vms --long 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "VBoxManage a échoué (code $LASTEXITCODE). Vérifie le chemin et les droits du compte Windows."
}

$machines = @()
$blocks = [regex]::Split(($raw -join [Environment]::NewLine), '\r?\n\s*\r?\n')
foreach ($block in $blocks) {
    $values = @{}
    foreach ($line in ($block -split '\r?\n')) {
        if ($line -match '^\s*([^:]+):\s*(.*?)\s*$') {
            $values[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    if (-not $values.ContainsKey("UUID")) { continue }

    $state = [string]$values["State"]
    if ($state -match '^([^(]+)') { $state = $matches[1].Trim() }
    $memory = $null
    if ($values["Memory size"] -match '(\d+)') { $memory = [int]$matches[1] }
    $cpu = $null
    if ($values["Number of CPUs"] -match '(\d+)') { $cpu = [int]$matches[1] }

    $vmName = [string]$values["UUID"]
    if ($values["Name"]) { $vmName = [string]$values["Name"] }

    $machines += @{
        id = [string]$values["UUID"]
        name = $vmName
        state = $state
        metadata = @{
            guest_os = [string]$values["Guest OS"]
            memory_mb = $memory
            cpu_count = $cpu
            groups = [string]$values["Groups"]
            host_collector = "windows-vboxmanage"
        }
    }
}

$body = @{ machines = $machines } | ConvertTo-Json -Depth 8
$headers = @{ "X-Collector-Token" = $collectorToken }
$uri = $ApiUrl.TrimEnd("/") + "/api/hypervisors/virtualbox/ingest"
try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -ContentType "application/json" -Body $body
    Write-Host ("Inventaire transmis : {0} VM(s) ; horodatage API : {1}" -f $response.received, $response.timestamp)
}
finally {
    $collectorToken = $null
    $secureToken.Dispose()
}
