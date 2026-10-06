<#
.SYNOPSIS
  Registers (or replaces) the "Kharibulbul Agent" scheduled task that runs the agent as SYSTEM at startup.
#>
param(
  [string]$Python = "python",
  [string]$Target = "C:\Program Files\Kharibulbul\agent",
  [string]$Config = ""
)
$ErrorActionPreference = "Stop"
if (-not $Config) { $Config = Join-Path $Target "config\agent-windows.yml" }
$taskName = "Kharibulbul Agent"
$action = New-ScheduledTaskAction -Execute $Python -Argument "-m kharibulbul agent -c `"$Config`"" -WorkingDirectory $Target
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650) -MultipleInstances IgnoreNew -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Kharibulbul SIEM log agent (Bülbül)" | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "[*] Task '$taskName' registered and started"
