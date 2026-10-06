# PB-001 · Brute force / password spraying / credential stuffing

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-WIN-001 | ≥10 failed Windows logons (4625) from one IP → one host in 5 min |
| KB-WIN-002 | one IP, ≥8 different user names failing in 10 min (spraying) |
| KB-WIN-003 | account locked out (4740) |
| KB-WIN-006 | Kerberos / NTLM failure burst on the DC |
| KB-LNX-001 / 002 / 005 | sshd failures, user enumeration, slow brute force then success |
| KB-WEB-002 | POST to a login page failing ≥5 times |
| **KB-COR-001 / 002** | **failures then a SUCCESS from the same IP – treat as compromised credential** |

## 2. Severity & SLA (lab targets)
* high → acknowledge within 15 min, first triage within 1 h
* critical (KB-COR-*) → acknowledge within 5 min, containment within 30 min

## 3. Triage (Events page / `kharibulbul query`)
```kql
# what did the source do? (last 24 h)
source.ip:10.10.99.10
# failures per user
event.action:(logon-failed OR ssh-login-failed) AND source.ip:10.10.99.10        -> side panel "Actions"/"Users"
# any success at all from that IP?
event.outcome:success AND source.ip:10.10.99.10
# is the account active elsewhere?
user.name:aysel AND event.category:authentication
# after a success: what ran?
host.name:ws01 AND event.action:process-created AND user.name:aysel
```
Questions to answer:
1. Is the source inside the lab (`source.geo.name` = Lab-*) or unknown? Which zone?
2. Which accounts were targeted – one (brute force) or many (spraying)? Any privileged (`administrator`, `root`, `svc_*`)?
3. Did any attempt succeed (KB-COR-001/002, `event.outcome:success`)? What logon type (`winlog.logon.type`: network=SMB/RPC, remote-interactive=RDP)?
4. Reason codes: `winlog.logon.failure.reason` – *user does not exist* (enumeration) vs *wrong password*.

## 4. Containment
* **No success:** block the source at the host firewall / UFW (`ufw deny from <ip>`; `netsh advfirewall firewall add rule name="KB block" dir=in action=block remoteip=<ip>`), keep monitoring.
* **Success:** disable the account (`Disable-ADAccount` / `usermod -L`), force logoff (`logoff <session>` / `pkill -KILL -u user`), isolate the host from the lab switch/VLAN, reset the password from a clean admin workstation.
* Lockouts: unlock only after confirming the source is stopped.

## 5. Eradication & recovery
* Check the host for persistence (run PB-008 checks) if a success happened.
* Enforce lockout policy / fail2ban / `MaxAuthTries`, disable password SSH auth where possible, no RDP from workstation VLAN.
* Re-enable the account with a new password and MFA (if available).

## 6. Evidence
* `kharibulbul alerts --json > evidence/alert-<id>.json`
* `kharibulbul query "source.ip:<ip>" --since now-24h --json > evidence/events-<ip>.json`
* Screenshot of the alert drawer (sample events) and the Overview "Top source IPs" panel.

## 7. False positives & tuning
* A service account failing every minute (expired password) – fix the service; temporarily add `filter_service: {user.name: svc_backup}` to the rule and `condition: selection and not filter_service`.
* Vulnerability scanner with credentials – add its IP in a `filter_scanner: {source.ip: 10.10.10.50}` selection.
* Raise `threshold.count` if a shared jump host generates legitimate volume.

## 8. Close-out
* Set status *closed* with notes: source, accounts, success yes/no, containment done.
* If confirmed compromise: also create an entry in the incident log (docs/OPERATIONS.md § Incident log).
