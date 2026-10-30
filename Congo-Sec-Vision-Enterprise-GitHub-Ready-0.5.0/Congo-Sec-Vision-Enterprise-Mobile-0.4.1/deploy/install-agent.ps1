param(
  [Parameter(Mandatory=$true)][string]$Server,
  [Parameter(Mandatory=$true)][string]$EnrollmentToken,
  [int]$Interval = 60
)
$ErrorActionPreference = "Stop"
$InstallDir = "$env:ProgramFiles\CongoSecVisionAgent"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item "$PSScriptRoot\..\agent\agent.py" "$InstallDir\agent.py" -Force
Copy-Item "$PSScriptRoot\..\agent\requirements.txt" "$InstallDir\requirements.txt" -Force
py -m pip install -r "$InstallDir\requirements.txt"
$Action = New-ScheduledTaskAction -Execute "py.exe" -Argument "`"$InstallDir\agent.py`" --server `"$Server`" --enrollment-token `"$EnrollmentToken`" --interval $Interval"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "CongoSecVisionAgent" -Action $Action -Trigger $Trigger -Principal $Principal -Force
Start-ScheduledTask -TaskName "CongoSecVisionAgent"
Write-Host "Agent task installed. Verify its first heartbeat in the Congo Sec Vision console."
