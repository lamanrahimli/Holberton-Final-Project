<#
.SYNOPSIS
  Turns on the Windows audit settings the Kharibulbul rules rely on (run as Administrator).
  - Logon / account management / policy change auditing (4624/4625/4720/4732/4719/1102 ...)
  - Process creation with command line (4688 + CommandLine)
  - PowerShell script block + module logging (4104/4103)
  - Windows Firewall dropped-packet log (pfirewall.log) for port-scan detection
  - Scheduled task / service auditing (4698/4697)
#>
$ErrorActionPreference = "Continue"
Write-Host "[*] Advanced audit policy"
$subcats = @(
  "Logon", "Logoff", "Account Lockout", "Special Logon", "Other Logon/Logoff Events",
  "Credential Validation", "Kerberos Authentication Service", "Kerberos Service Ticket Operations",
  "User Account Management", "Security Group Management", "Computer Account Management",
  "Process Creation", "Process Termination",
  "Audit Policy Change", "Authentication Policy Change", "Authorization Policy Change",
  "Security System Extension", "System Integrity", "Other Object Access Events",
  "File Share", "Detailed File Share", "Sensitive Privilege Use", "Other System Events"
)
foreach ($s in $subcats) { auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }
# WFP connection auditing (5156/5157) is very noisy; enable only failure (blocked) for scan visibility
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable | Out-Null

Write-Host "[*] Command line in 4688"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

Write-Host "[*] PowerShell script block + module logging"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"

Write-Host "[*] Windows Firewall logging of dropped connections -> C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 8192 | Out-Null

Write-Host "[*] Bigger Security log (256 MB) so nothing is lost between agent polls"
wevtutil sl Security /ms:268435456
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456 2>$null

Write-Host "[*] Enabling TaskScheduler operational log"
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true 2>$null

Write-Host "Done. Verify with: auditpol /get /category:*"
