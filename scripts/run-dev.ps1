<#
.SYNOPSIS
  Developer / demo launcher on Windows: creates a venv, installs deps, validates rules and starts the server.
  Open http://127.0.0.1:8080/ afterwards and run  .\scripts\run-dev.ps1 -Simulate  in another window.
  -WindowsAgent starts the Bülbül agent on this machine (no admin rights needed).
  -WslSetup / -WslAgent / -WslActivity run the Linux agent inside WSL 2 (Ubuntu) through scripts/wsl-agent.sh.
#>
param([switch]$Simulate, [switch]$Agent, [switch]$WindowsAgent, [switch]$WslSetup, [switch]$WslAgent, [switch]$WslActivity, [switch]$Tests)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repo
$venv = Join-Path $repo ".venv"
if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
  $py = (Get-Command python -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike "*WindowsApps*" } | Select-Object -First 1).Source
  if (-not $py) { $py = "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python312\python.exe" }
  Write-Host "[*] Creating venv with $py"
  & $py -m venv $venv
  & (Join-Path $venv "Scripts\python.exe") -m pip install --quiet --disable-pip-version-check -r requirements.txt
  & (Join-Path $venv "Scripts\python.exe") -m pip install --quiet --disable-pip-version-check -e .
}
$python = Join-Path $venv "Scripts\python.exe"
if ($Tests) { & $python -m pytest -q; exit $LASTEXITCODE }
if ($Simulate) { & $python -m kharibulbul simulate all; exit $LASTEXITCODE }
if ($Agent) { & $python -m kharibulbul agent -c config\agent-windows.yml; exit $LASTEXITCODE }
if ($WindowsAgent) { & $python -m kharibulbul agent -c config\agent-windows-host.yml; exit $LASTEXITCODE }
if ($WslSetup) { wsl -d Ubuntu -u root bash scripts/wsl-agent.sh setup; exit $LASTEXITCODE }
if ($WslAgent) { wsl -d Ubuntu -u root bash scripts/wsl-agent.sh run; exit $LASTEXITCODE }
if ($WslActivity) { wsl -d Ubuntu -u root bash scripts/wsl-agent.sh activity; exit $LASTEXITCODE }
& $python -m kharibulbul rules validate rules
& $python -m kharibulbul server -c config\server.yml
