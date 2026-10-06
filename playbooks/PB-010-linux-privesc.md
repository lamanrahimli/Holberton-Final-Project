# PB-010 · Linux privilege escalation and remote script execution

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-LNX-010 | repeated sudo failures for one user |
| KB-LNX-013 | download piped into a shell (curl \| bash) |
| KB-LNX-014 | failed su to root |
| KB-LNX-015 | sudo used to open a root shell / editor (hunting, low) |

## 2. Severity & SLA
* medium → review within 1 h.
* high (KB-LNX-013) → acknowledge within 15 min; a remote script executed as root is a full compromise until proven otherwise.

## 3. Triage
```kql
host.name:<host> AND user.name:<user> AND event.dataset:linux.auth              -> the user's auth/sudo timeline
host.name:<host> AND event.action:sudo-command                                   -> every privileged command on the host
host.name:<host> AND event.action:(ssh-login-success OR session-started)         -> how / from where the user got in (source.ip)
host.name:<host> AND event.category:iam                                          -> accounts or groups changed afterwards
host.name:<host> AND event.action:cron-command                                   -> persistence via cron (PB-008)
"<url from the command line>"                                                    -> the same URL on other hosts
```
Questions:
1. Is the user expected to administer this host (`kharibulbul.asset.owner`, host role)? Ask them directly – in a lab it is often a teammate.
2. For KB-LNX-013: what did the script do? If the lab keeps the file (`/tmp`, shell history), review it offline. Look at the sudo commands that follow.
3. Did the failures turn into a success (KB-LNX-005 / `event.outcome:success` after the failures)?
4. Any new users, groups or cron entries in the following 30 minutes (KB-COR-003, KB-LNX-011, KB-LNX-016)?

## 4. Containment
* Unexpected root activity: terminate the session (`pkill -KILL -u <user>`), lock the account (`usermod -L`), block the source IP.
* Preserve `/var/log/auth.log`, `~/.bash_history`, `/etc/sudoers*`, `/etc/passwd`, `/etc/group`, cron directories (copy to the evidence share before changes).
* Rotate root's and the affected user's credentials/keys.

## 5. Eradication & recovery
* Remove any added accounts, group memberships, cron jobs, SSH keys (`~/.ssh/authorized_keys` for every user) and set-uid binaries created after `first_seen`.
* Reimage if the remote script ran as root and its content is unknown.
* Harden: `Defaults use_pty, log_input, log_output` in sudoers, `PermitRootLogin no`, fail2ban, no password-less sudo for students.

## 6. Evidence
Alert JSON, sudo/auth timeline export, the script/URL involved, list of changes found.

## 7. False positives & tuning
* Teammates mistyping their password (KB-LNX-010): raise `threshold.count` to 5 or filter the lab admin users.
* Official installers documented as `curl … | bash` (Docker, Rust, Node): filter the exact URL in KB-LNX-013 with `filter_known: {process.command_line|contains: [get.docker.com]}` and record the approval in the notes.
* KB-LNX-015 is a hunting rule: keep it low severity or disable it outside exercises.

## 8. Close-out
Notes: user, host, authorised yes/no, script content summary, credentials rotated, persistence removed.
