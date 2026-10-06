# PB-008 · Persistence: services, scheduled tasks, autorun keys, cron

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-WIN-030 / 031 | service installed (suspicious path / inventory) |
| KB-WIN-032 / 033 | scheduled task with suspicious action / inventory |
| KB-SYS-070 | autorun registry value set (Run, RunOnce, Winlogon, IFEO) |
| KB-LNX-016 | cron job that downloads or runs from temp paths |

## 2. Severity & SLA
* high → acknowledge within 15 min.
* low inventory rules (KB-WIN-031/033) → review daily; they build the allow-list.

## 3. Triage
```kql
host.name:<host> AND event.action:(service-installed OR scheduled-task-created OR registry-value-set)   -> all persistence changes
host.name:<host> AND service.name:<name>                                          -> service lifecycle (7045 → 7036 state changes)
host.name:<host> AND winlog.task.name:<task>                                      -> task created / updated / started
host.name:<host> AND event.action:process-created AND user.name:<actor>           -> what the actor ran around that time
host.name:<host> AND process.executable:"<path from service.path or task command>"  -> has the persisted binary already executed?
```
Questions:
1. Who created it (`user.name`) and is there a change record? Installers and update agents are normal; a user account at night is not.
2. Where does the binary live (`service.path`, `process.command_line`, `registry.data.strings`)? Temp / Public / AppData → suspicious.
3. Has it run yet, and did it produce network activity (PB-009)?
4. Same artefact on other hosts? Search by service name / task name / hash across the fleet.

## 4. Containment
* Disable the mechanism: `Stop-Service` + `Set-Service -StartupType Disabled`, `Disable-ScheduledTask`, remove the autorun value (export it first: `reg export`), comment out the cron line.
* Quarantine the referenced binary (move to an evidence folder, hash it) and add the hash to `intel/hashes.txt`.
* If the actor account is not an admin who can explain it → treat as compromised (PB-004 containment).

## 5. Eradication & recovery
* Remove the service / task / key / cron entry after evidence collection; reboot and confirm nothing recreates it (watch KB-WIN-030/032, KB-SYS-070 for the host).
* Check the other persistence locations the rules do not cover yet (WMI subscriptions – Sysmon 19/20/21 are logged; startup folders – Sysmon 11 on `Startup\`).
* Hardening: restrict service creation rights, use `Deny log on as a batch job` for regular users, AppLocker for user-writable paths.

## 6. Evidence
Alert JSON, exported registry key / task XML (`schtasks /query /xml /tn <task>`) / service configuration (`sc qc <name>`), binary hash.

## 7. False positives & tuning
* Software deployment (Intune/SCCM/Chocolatey) creates services and tasks constantly: filter by `user.name` (deployment account) and by installer parent process in KB-WIN-030/032 and KB-SYS-070 `filter_installers`.
* Move recurring benign names from the inventory alerts into a filter selection so only *new* names alert.

## 8. Close-out
Notes: mechanism, binary, actor, removed yes/no, fleet-wide check done.
