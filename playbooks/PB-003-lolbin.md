# PB-003 · Living-off-the-land binaries & suspicious PowerShell

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-SYS-010 certutil | download / decode with certutil |
| KB-SYS-011 mshta · 012 rundll32 · 013 regsvr32 | script/COM execution through signed Windows binaries |
| KB-SYS-014 bitsadmin · 015 wmic · 016 wscript/cscript | download, remote process creation, script from user dirs |
| KB-SYS-017 / 018 | bursts or chains of discovery commands (whoami, net, ipconfig…) |
| KB-SYS-020 · KB-PS-001 · KB-PS-002 | encoded PowerShell, download cradle, hidden+bypass launcher |

These binaries are legitimate, so **context decides**: parent process, user, command line, what happened next.

## 2. Severity & SLA
high → acknowledge within 15 min. Treat as *active hands-on-keyboard or malware stage 1* until proven otherwise.

## 3. Triage
```kql
host.name:<host> AND event.action:process-created AND user.name:<user>      -> full process timeline (sort asc)
host.name:<host> AND process.parent.name:<parent>                            -> what else did the parent spawn?
host.name:<host> AND event.code:3 AND process.name:(certutil.exe OR powershell.exe OR mshta.exe)  -> outbound connections
host.name:<host> AND event.action:dns-query                                  -> names resolved around that time
host.name:<host> AND event.action:file-created AND file.extension:(exe OR dll OR ps1 OR hta OR vbs)   -> dropped files
"kb-test"                                                                    -> free-text search for the payload name/URL seen in the command line
```
Decode encoded PowerShell in the lab (never on the affected host):
`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))`

Questions:
1. Who launched it (`user.name`) and from what (`process.parent.name` – explorer = user typed it; winword/outlook = phishing; services/wmiprvse = remote execution)?
2. Does the command line reference a URL, an unusual path (Temp, Public, AppData) or base64?
3. Did a file get written and executed afterwards (KB-SYS-050, KB-COR-005)?
4. Any network connection / DNS from the same process within ±5 minutes?

## 4. Containment
* Confirmed malicious: isolate the host, kill the process tree (`Stop-Process -Id <pid> -Force` / `taskkill /PID <pid> /T /F`), capture the dropped file (hash it: `Get-FileHash`), add the hash / URL / IP to `intel/` lists so every other host is checked automatically.
* Block the download host at the firewall / DNS sinkhole (`intel/domains.txt` + DNS server policy).

## 5. Eradication & recovery
* Remove dropped files and persistence (PB-008), reset the user's password if credentials may be exposed.
* Application control for the lab: AppLocker/WDAC rule blocking mshta/regsvr32/certutil for standard users, PowerShell Constrained Language Mode.

## 6. Evidence
* Alert JSON + full process timeline export (`kharibulbul query "host.name:<host> AND event.action:process-created" --since now-2h --json`).
* Copy of the decoded command / script block text.

## 7. False positives & tuning
* Admin scripts that legitimately use `certutil -hashfile` (not matched) or `bitsadmin` for updates: add `filter_admin: {user.name: [deploy-svc], process.parent.name: [sccm-agent.exe]}`.
* Developers running `wmic process call create` in build scripts: filter by `process.parent.name`.
* Chained recon (KB-SYS-018) by inventory scripts: filter the script's parent command line.

## 8. Close-out
Notes: binary, decoded command, source of execution, dropped files, indicators added to `intel/`.
