# PB-005 · Log clearing, audit tampering, sensor tampering

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-WIN-020 | Security log (1102) or another channel (104) cleared |
| KB-WIN-021 | audit policy changed (4719) |
| KB-WIN-022 / KB-SYS-071 | Defender disabled (events or registry) |
| KB-WIN-024 | Sysmon stopped / reconfigured |
| KB-KB-001 | agent silent longer than `agents.heartbeat_timeout` |

Anti-forensics is rarely accidental. Assume something happened *before* the clearing and use the SIEM copy of the logs – that is exactly why they are shipped off-host.

## 2. Severity & SLA
high → acknowledge within 15 min. If the host also has other alerts in the last 24 h, escalate to critical.

## 3. Triage
```kql
host.name:<host>                                                   -> everything we still have (the SIEM keeps events the host lost)
host.name:<host> AND event.category:authentication AND event.outcome:success   -> who was logged on when it happened
host.name:<host> AND event.action:process-created AND process.name:(wevtutil.exe OR powershell.exe OR auditpol.exe OR sc.exe OR net.exe)
host.name:<host> AND (event.action:service-state-changed OR event.action:service-start-type-changed)   -> sensor services touched?
agent.name:<agent>                                                 -> last events before silence (KB-KB-001)
```
Questions:
1. Who cleared it (`user.name` in the 1102 event) and were they interactive on the host (`winlog.logon.type`)?
2. What happened in the 60 minutes before? Look for LOLBins (PB-003), new accounts (PB-004), services/tasks (PB-008).
3. For KB-KB-001: is the host just powered off (planned)? Ping it, check the hypervisor. If it is up but silent, the agent or its network path was tampered with.
4. Defender / Sysmon changes: which process made the registry change (`process.name` in Sysmon 13)?

## 4. Containment
* Isolate the host if any suspicious activity preceded the clearing.
* Re-enable Defender / restart Sysmon (`Restart-Service Sysmon64`) and the agent (`Start-ScheduledTask "Kharibulbul Agent"`).
* Preserve volatile evidence before reboot: `Get-Process`, `Get-NetTCPConnection`, scheduled tasks, services (export to the evidence folder).

## 5. Eradication & recovery
* Reapply `scripts/enable-audit-policy.ps1` and `scripts/enable-sysmon.ps1`.
* Restrict who can clear logs (remove `SeSecurityPrivilege` from non-admins), protect the agent task (SYSTEM only).

## 6. Evidence
Alert JSON, export of the last 2 h of host events from Kharibulbul (this *is* the surviving copy), screenshots of the audit policy (`auditpol /get /category:*`).

## 7. False positives & tuning
* Planned log rotation by an admin script: document it and filter `user.name: log-rotate-svc` for KB-WIN-020 only.
* KB-KB-001 for lab VMs that are switched off after class: set `agents.heartbeat_timeout` higher or close the alert with the note "planned shutdown".

## 8. Close-out
Notes: what was cleared / changed, by whom, preceding activity found (yes/no), controls restored.
