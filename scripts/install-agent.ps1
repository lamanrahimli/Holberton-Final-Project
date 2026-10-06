<#
.SYNOPSIS
  Installs the Bülbül (Kharibulbul) agent on a Windows host: Python check, files, config, scheduled task at boot.
.EXAMPLE
  PS> Set-ExecutionPolicy -Scope Process Bypass; .\scripts\install-agent.ps1 -ServerIp 10.10.10.5
.NOTES
  Run in an elevated PowerShell (Administrator). Reading the Security log requires it.
#>
param(
  [Parameter(Mandatory = $true)][string]$ServerIp,
  [string]$Target = "C:\Program Files\Kharibulbul\agent",
  [string]$SharedSecret = "",
  [switch]$InstallSysmon,
  [switch]$EnableAuditPolicy
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Find-Python {
  foreach ($c in @("python", "py")) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*WindowsApps*") {
      $v = & $cmd.Source --version 2>&1
      if ($v -match "3\.(1[0-9]|[2-9][0-9])") { return $cmd.Source }
    }
  }
  return $null
}

$python = Find-Python
if (-not $python) {
  Write-Host "[*] Python 3.10+ not found - installing via winget"
  winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
  $python = Find-Python
  if (-not $python) { throw "Python installation failed - install it manually from python.org and re-run." }
}
Write-Host "[*] Using $python"

Write-Host "[*] Copying agent files to $Target"
New-Item -ItemType Directory -Force -Path $Target | Out-Null
foreach ($item in @("kharibulbul", "config", "pyproject.toml", "requirements.txt", "README.md")) {
  Copy-Item -Recurse -Force (Join-Path $repo $item) $Target
}
New-Item -ItemType Directory -Force -Path (Join-Path $Target "data") | Out-Null

Write-Host "[*] Installing dependencies"
& $python -m pip install --quiet --disable-pip-version-check pyyaml
& $python -m pip install --quiet --disable-pip-version-check --no-deps -e $Target

Write-Host "[*] Writing config (server $ServerIp)"
$cfgPath = Join-Path $Target "config\agent-windows.yml"
$cfg = Get-Content $cfgPath -Raw
$cfg = $cfg -replace "host: 10\.10\.10\.5", "host: $ServerIp"
if ($SharedSecret) { $cfg = $cfg -replace 'shared_secret: "\$\{KB_SHARED_SECRET:-\}"', "shared_secret: `"$SharedSecret`"" }
Set-Content -Path $cfgPath -Value $cfg -Encoding utf8

if ($EnableAuditPolicy) { & (Join-Path $repo "scripts\enable-audit-policy.ps1") }
if ($InstallSysmon) { & (Join-Path $repo "scripts\enable-sysmon.ps1") }

Write-Host "[*] Registering scheduled task 'Kharibulbul Agent' (runs as SYSTEM at startup)"
& (Join-Path $repo "scripts\register-agent-task.ps1") -Python $python -Target $Target
Write-Host ""
Write-Host "Done. Task status: Get-ScheduledTask 'Kharibulbul Agent' | Get-ScheduledTaskInfo"
Write-Host "Manual run:       & '$python' -m kharibulbul agent -c '$cfgPath'"
