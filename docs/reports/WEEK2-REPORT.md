# Week 2 report — parsing, ECS-style normalisation, enrichment

*Executed 2026-09-27. Measurements produced by the pipeline itself (`kharibulbul parse`, a
coverage script over `samples/`), tests in `tests/test_parsers.py` and `tests/test_parsers_week2.py`.*

## 1. Parsers added this week (on top of the base set)

| Parser | Dataset(s) | Fields produced (highlights) | Sample | Tests |
|--------|-----------|-------------------------------|--------|-------|
| `auditd.py` | `linux.auditd` | `auditd.type/serial/key/login_uid`, hex-decoded `cmd`/`proctitle`/`a0..aN`, `process.*`, `user.*`, `source.ip`, standard actions (`auth-failed`, `logon-success`, `sudo-command`, `process-executed`, `user-created`, `service-stopped`, `auditd-config-change`) | `samples/audit.log` (23 lines) | 2 |
| `apache_error.py` | `nginx.error`, `apache.error` | `log.level`, `source.ip/port`, `http.request.method`, `url.path`, `file.path`, `error.code` (AHxxxxx), `error.message`, tag `sensitive-path` | `samples/nginx-error.log`, `samples/apache-error.log` | 2 |
| `windows_dhcp.py` | `windows.dhcp` | `event.code` (DHCP id), `event.action` (`dhcp-lease-assigned/renewed/released`, `dhcp-ip-conflict`, `dhcp-lease-denied`…), `client.ip/mac/domain`, `dhcp.transaction_id`; header lines skipped | `samples/DhcpSrvLog-Sat.log` | 1 |
| fail2ban sub-parser (`syslog.py`) | `linux.fail2ban` | `event.action` (`fail2ban-ban/unban/found/restore-ban`), `source.ip`, `rule.name` (jail), `event.type` denied/allowed | `samples/fail2ban.log` | 1 |
| time context (`normalize.py`) | all | `kharibulbul.time.hour`, `.weekday`, `.business_hours` from `pipeline.timezone_offset_hours` (4 = Baku) and `business_hours: [8, 19]` | – | 1 |

Parser selection was extended with content sniffing for `type=`/`node=` (auditd) and the nginx /
Apache error-log timestamp shapes; the sniff window was widened from 16 to 48 bytes after a test
showed the nginx pattern could not match (bug found by `tests/test_parsers_week2.py`).

Other fixes surfaced by real data: `su` PAM failures (`pam_unix(su:auth): authentication failure`)
are now `su-failed` (were mis-classified as success).

## 2. Coverage measurement

Specific-parser coverage over every sample file (`generic` = fallback parser, `dropped` = empty):

| File | Lines | Specific parser | Coverage |
|------|------:|-----------------|---------:|
| auth.log | 40 | syslog (sshd/sudo/su/useradd/usermod/cron/logind) | 100 % |
| ufw.log | 25 | syslog → kernel/UFW | 100 % |
| nginx-access.log | 31 | web | 100 % |
| audit.log | 23 | auditd | 100 % |
| nginx-error.log | 9 | apache_error | 100 % |
| apache-error.log | 7 | apache_error | 100 % |
| fail2ban.log | 10 | syslog → fail2ban | 100 % |
| DhcpSrvLog-Sat.log | 17 | windows_dhcp | 7 data rows = 100 %; the 10 "generic" lines are the file's text header |
| **Total** | **162** | | **93.8 %** (100 % of real log rows) |

Without any dataset hint (pure content sniffing) 145/162 lines (89.5 %) still reach a specific
parser — the remaining ones are syslog-shaped lines whose dataset only the agent knows.

Synthetic Windows / Sysmon / PowerShell / RDP / Defender / DHCP / firewall records from all 52
scenarios: **100 % parsed, 0 parser errors** (`kharibulbul rules coverage`, 671 events).

## 3. Field mapping (excerpt; full dictionary in `docs/SCHEMA.md`, `GET /api/schema`)

| Source field | KES field | Notes |
|--------------|-----------|-------|
| Security `TargetUserName` / `TargetDomainName` | `user.name` / `user.domain` (logon events), `user.target.name` (IAM events) | subject vs target distinction kept |
| Security `LogonType` | `winlog.logon.type` | numeric → word (`network`, `remote-interactive`…) |
| Security `SubStatus`/`Status` | `winlog.logon.failure.status` / `.reason` | reason text table |
| Sysmon `Image` / `CommandLine` / `Hashes` | `process.executable` / `process.name` / `process.command_line` / `process.hash.*` | name lower-cased, hashes split |
| Sysmon `QueryName` / `QueryResults` | `dns.question.name` / `dns.answers.data` | plus registered domain, TLD, `suspicious-tld` tag |
| sshd message | `event.action`, `user.name`, `source.ip/port`, `kharibulbul.auth.method` | 8 message shapes |
| UFW `SRC/DST/SPT/DPT/PROTO` | `source.*`, `destination.*`, `network.transport`, `network.direction` | direction from `IN=`/`OUT=` |
| auditd `msg='... addr=… acct=… res=…'` | `source.ip`, `user.name`, `event.outcome` | inner key/value block parsed, hex fields decoded |
| DHCP CSV columns | `client.ip`, `client.mac`, `client.domain`, `event.code` | MAC normalised `aa:bb:cc:dd:ee:ff` |

## 4. Enrichment verified

* Lab zones from `geoip/custom_ranges.csv` (`source.geo.name: Lab-Attacker` for 10.10.99.0/24), private-range fallback, MaxMind optional.
* Asset inventory (`config/assets.yml`): `host.role`, `kharibulbul.asset.criticality` (dc01 = critical → severity boost visible in alerts).
* Threat intel: `intel/*.txt` matched on IP, domain and hash (`KB-TI-001..003` all fire in the matrix).
* Direction: `network.direction` / `kharibulbul.network.zone_direction` from `pipeline.lab_networks`.
* New: `kharibulbul.time.*` enables the out-of-hours rules (`KB-WIN-007`, `KB-NET-032`).

## 5. Checklist status (from `docs/WEEK2.md`)

- [x] mapping tables · [x] coverage measured · [x] new parser(s) with tests (four, not one)
- [x] normalisation review on real + synthetic data · [x] GeoIP zones · [x] assets · [x] intel test
- [ ] MaxMind GeoLite2 file (needs an account; optional) · [ ] OpenSearch mirror demo (optional, needs a VM)
