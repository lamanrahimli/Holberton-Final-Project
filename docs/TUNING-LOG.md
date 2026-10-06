# Tuning log

One line per change to a rule, parser or scenario made because of observed behaviour.
Format: date | item | symptom (what was seen) | change | result.

| Date | Item | Symptom | Change | Result |
|------|------|---------|--------|--------|
| 2026-09-27 | KB-SYS-010…018, KB-SYS-030, KB-PS-*, KB-SYS-020 | none of the LOLBin/PowerShell rules fired on Sysmon events (`lolbin` scenario: 0 alerts) | Sysmon docs now carry `event.module: windows` (was `sysmon`) so `logsource: {module: windows}` covers Security 4688 *and* Sysmon 1 | 8/8 LOLBin rules fire; matrix green |
| 2026-09-27 | KB-LNX-002 (user enumeration) | threshold needs 5 distinct invalid users; scenario only produced 2 | scenario `ssh-brute-force` uses 6 non-existent accounts (realistic dictionary) | fires |
| 2026-09-27 | KB-LNX-010 (sudo failures) | one summary line "3 incorrect password attempts" counted as 1 event | scenario emits the three `pam_unix(sudo:auth)` failure lines PAM really writes before the summary | fires with count 3 |
| 2026-09-27 | simulator timestamps | events stamped up to minutes in the future → hidden by `to=now` dashboards (89 of 245 visible) | `generate()` measures the scenario span first and shifts the timeline to end 5 s before now | 246/246 visible |
| 2026-09-27 | alert entity label | `name=ws01, ip=…` ambiguous | full field names in the entity (`host.name=ws01, source.ip=…`) | readable in UI/CLI |
| 2026-09-27 | rules/sysmon/lolbin.yml | YAML error: description contained `javascript:/vbscript: protocol` (unquoted `: `) | quoted descriptions; rule validate is part of the checklist | 95/95 load |
| 2026-09-27 | file input (agent) | line re-read after a tiny file grew (17 events instead of 16) | identity = `st_dev:st_ino` on all platforms instead of hashing the first 256 bytes | no duplicates |
| 2026-09-27 | pipeline sniffing | nginx error lines without dataset hint fell to `generic` (`[crit]` level lost) | sniff window 16 → 48 bytes | 89.5 % of hint-less sample lines reach a specific parser |
| 2026-09-27 | `su` parser | `pam_unix(su:auth): authentication failure` classified as success | failure also detected on "authentication failure" | KB-LNX-014 fires |
| 2026-09-27 | KB-WEB-003 (scanner UA) | generic clients (`python-requests`, `curl/`, `wget/`) would alert on every script | `filter_generic` excludes them; dedicated scanners (Nikto, sqlmap, nuclei…) still alert | fewer FPs, still fires on Nikto/sqlmap |
| 2026-09-27 | KB-NET-020 (outbound uncommon port) | would alert on browsers/Teams and on 80/443/53 | `filter_common_ports` + `filter_known` process list | fires only for user-dir binaries on odd ports |
| 2026-09-27 | KB-NET-014 (DNS burst per domain) | big-vendor CDNs would trip the 60-query threshold | `filter_known` registered domains (microsoft.com, office.com, msedge.net, lab.local …) | `dns-beacon` fires, baseline quiet |
| 2026-09-27 | KB-LNX-017 (sudo by non-admin) | needs the lab's admin list | `filter_admins: [root, ops, ansible, sysadmin]` documented as lab-specific | fires for `aysel` in `linux-privilege` |
| 2026-09-27 | KB-KB-002, KB-WIN-005/012/031/033, KB-LNX-004/015, KB-PS-002 | no playbook linked (found by `tests/test_playbooks.py`) | playbooks assigned; test keeps it that way | 95/95 linked |
| 2026-09-27 | KB-COR-006 (RDP → service) | count shows all stage-1 matches (baseline RDP-type logons) | accepted; playbook PB-008 tells the analyst to read `sample_events` | – |
| 2026-09-28 | KB-NET-032 (DHCP lease out of hours) / scenario `dhcp` | rule fired in the 22:38 coverage run but not in a 13:03 live `simulate all` (93/95) - the scenario stamped its leases with the current time, so the result depended on the wall clock | scenario adds a lease record pinned to 22:30 UTC (02:30 lab time), like `after-hours-logon`; `EXPECTED["dhcp"]` now includes KB-NET-032 | fires at any time of day; 94/95 live and in the matrix |
| 2026-09-30 | agent shipper | 100 PowerShell 4104 events = 1.1 MB in one protocol line, above the server's 1 MiB `ingest.max_line_bytes`: `line too long`, endless reconnect loop, nothing delivered | batches split below `batch.max_bytes` (512 KiB), back-off after a rejected send, spool keeps only the undelivered rest | backlog delivered, 0 rejected lines |
| 2026-09-30 | `su` parser (real Ubuntu journal) | one mistyped `su` password raised "authentication failures" by 2 (`pam_unix(su-l:auth)` line + `FAILED SU` line), a *successful* `su` raised it by 1 (`pam_systemd(su-l:session): Failed to check …` matched "FAILED"+"SU") and `session closed` lines counted as logons | explicit patterns: `FAILED SU`/`FAILED su for` → `su-failed`; `(to x) y on tty` → `su-success`; PAM auth line → `su-pam-auth-failure` (not an authentication failure); `su-session-opened/closed`; rest `su-message`. KB-LNX-014 matches `su-failed` or `su-pam-auth-failure` | live: correct password +0, one wrong password +1; KB-LNX-014 still fires |

## Open tuning ideas (for the lab weeks)

* KB-LNX-014 is titled "Failed su to root" but matches a failed `su` to any account (seen live with `user1 → user2`) — either add `user.effective.name: root` or rename it.

* KB-WIN-031 / KB-WIN-033 (inventory rules) will be noisy on real hosts during software deployment — move recurring benign names into filters after the first week of data.
* KB-SYS-050 (execution from user-writable dirs) — extend `filter_updaters` with whatever installers the lab actually uses.
* Raise `KB-WEB-001` threshold if a crawler/monitoring tool is introduced.
* `agents.heartbeat_timeout` should be longer than the longest planned VM pause in class.
