<#
.SYNOPSIS
  Downloads Sysmon (Microsoft Sysinternals) and installs it with the Kharibulbul configuration.
  In an isolated lab without internet: copy Sysmon.zip next to this script first.
#>
param([string]$ConfigPath = "")
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $ConfigPath) { $ConfigPath = Join-Path $repo "sysmon\kharibulbul-sysmon.xml" }
$work = Join-Path $env:TEMP "kharibulbul-sysmon"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$zip = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "Sysmon.zip"
if (-not (Test-Path $zip)) {
  $zip = Join-Path $work "Sysmon.zip"
  Write-Host "[*] Downloading Sysmon from Microsoft Sysinternals"
  Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip
}
Expand-Archive -Force -Path $zip -DestinationPath $work
$exe = Join-Path $work "Sysmon64.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path $work "Sysmon.exe" }
$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc) {
  Write-Host "[*] Sysmon already installed - updating configuration"
  & $exe -c $ConfigPath
} else {
  Write-Host "[*] Installing Sysmon with $ConfigPath"
  & $exe -accepteula -i $ConfigPath
}
Write-Host "[*] Latest Sysmon events:"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 | Format-Table TimeCreated, Id, Message -AutoSize -Wrap
