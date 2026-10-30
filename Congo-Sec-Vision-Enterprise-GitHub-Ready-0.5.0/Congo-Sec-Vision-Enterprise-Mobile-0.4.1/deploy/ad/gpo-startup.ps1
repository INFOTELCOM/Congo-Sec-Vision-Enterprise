$ErrorActionPreference = "Stop"
$Base = "$env:ProgramFiles\CongoSecVisionAgent"
New-Item -ItemType Directory -Force -Path $Base | Out-Null
Copy-Item "$PSScriptRoot\agent.py" "$Base\agent.py" -Force
Copy-Item "$PSScriptRoot\requirements.txt" "$Base\requirements.txt" -Force
if (-not (Get-Command py.exe -ErrorAction SilentlyContinue)) {
  Write-EventLog -LogName Application -Source "CongoSecVision" -EventId 4101 -EntryType Error -Message "Python launcher py.exe missing; agent not installed."
  exit 2
}
py -m pip install -r "$Base\requirements.txt"
$Server = Get-Content "$PSScriptRoot\server.txt" -Raw
$EnrollmentToken = Get-Content "$PSScriptRoot\enrollment-token.txt" -Raw
$Action = New-ScheduledTaskAction -Execute "py.exe" -Argument "`"$Base\agent.py`" --server `"$($Server.Trim())`" --enrollment-token `"$($EnrollmentToken.Trim())`" --interval 60"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "CongoSecVisionAgent" -Action $Action -Trigger $Trigger -Principal $Principal -Force
Start-ScheduledTask -TaskName "CongoSecVisionAgent"
