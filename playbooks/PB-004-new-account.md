# PB-004 · Account creation, privileged group changes, password resets

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-WIN-010 / KB-LNX-012 | new user created (4720 / useradd) |
| KB-WIN-011 / KB-LNX-011 | member added to Administrators, Domain Admins, sudo, wheel, docker… |
| KB-WIN-012 | account deleted / disabled |
| KB-WIN-013 | password reset by another user (4724) |
| **KB-COR-003** | **created *and* made privileged within 30 min – attacker backdoor account** |

## 2. Severity & SLA
* low/medium → review within the shift, confirm with the change log.
* high/critical → acknowledge within 15 min; a new admin nobody requested is a confirmed incident.

## 3. Triage
```kql
event.category:iam AND host.name:<host>                                   -> full account-management timeline
user.target.name:<newuser>                                                -> everything about the new account
user.name:<actor> AND event.category:authentication                       -> how did the actor log on (type, source.ip)?
user.name:<actor> AND event.action:process-created                        -> tools used (net.exe user /add, powershell, useradd)
user.name:<newuser> AND event.outcome:success                             -> has the new account been used already?
```
Questions:
1. Is there a ticket / change request for this account? Ask the owner (`kharibulbul.asset.owner`).
2. Who performed it (`user.name`) and from where (`source.ip`, `winlog.logon.type`)? An admin at 03:00 over RDP from a workstation is suspicious.
3. Naming convention: `svc_backup2`, `adm1n`, `support` look like look-alike accounts.
4. Has the account logged on, changed passwords, or been added to more groups?

## 4. Containment
* Unauthorised: disable the account immediately (`Disable-ADAccount` / `net user X /active:no` / `usermod -L X`), remove group memberships, terminate its sessions.
* Reset the *actor's* credentials too – its account was used to create the backdoor.
* Isolate the host if the actor's activity shows malware or LOLBins (PB-003/007).

## 5. Eradication & recovery
* Delete the account after evidence is collected; check for other accounts created by the same actor in the last 30 days.
* Review group policy: restrict who can create accounts, alert on `SeBackupPrivilege`/`SeDebugPrivilege` grants (KB-WIN-005 style rules).

## 6. Evidence
Alert JSON, IAM timeline export, screenshot of the group membership (`net localgroup administrators`, `getent group sudo`).

## 7. False positives & tuning
* Planned onboarding by the help desk: mark *false_positive* with the ticket number; optionally filter `user.name: helpdesk-svc` for KB-WIN-010 only (never for KB-WIN-011).
* Automation (Ansible / Intune) creating local admins: filter by actor and lower severity.

## 8. Close-out
Notes: account, actor, authorised yes/no, actions taken, ticket reference.
