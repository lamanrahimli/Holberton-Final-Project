<p align="center">
  <img src="kharibulbul/web/static/logo.png" width="160" alt="Kharibulbul logo - Xarıbülbül orchid with the nightingale">
</p>

<h1 align="center">Kharibulbul SIEM · Xarıbülbül SIEM</h1>
<p align="center"><b>A national mini-SIEM built from scratch</b> — agent, ingest pipeline, ECS-style schema, GeoIP/asset/intel enrichment, event store + query language, rule engine, alerting, dashboards, playbooks.<br>
Free, open source, runs in an isolated lab. Wazuh · OpenSearch · Beats · Sysmon were the <i>reference designs</i>; every component here is our own code.</p>

---

## Why "Kharibulbul"?

The Khari Bulbul (*Ophrys caucasica*) is the orchid of Shusha and Karabakh, a national symbol of
Azerbaijan. The lip of the flower looks like a nightingale (*bülbül*) sitting inside it. Our SIEM
sits inside the network and listens to every host the way the nightingale listens – hence the logo:
a green nightingale sitting in the violet-magenta Khari Bulbul orchid, outlined in gold (`kharibulbul/web/static/logo.png`); the dashboard keeps the flag colours as its accent palette.

## What is inside

| Layer | What we built | Where |
|-------|---------------|-------|
| Collection | **Bülbül agent**: file tail (rotation-safe), Windows Event Log/Sysmon via `wevtutil` with bookmarks, journald, command inputs; batching, acks, reconnect back-off, disk spool | `kharibulbul/agent/` |
| Transport | newline-JSON agent protocol (hello/batch/ack/heartbeat) over TCP, optional TLS/mTLS + shared secret; syslog UDP/TCP; HTTP ingest | `kharibulbul/server/ingest.py` |
| Parsing | Windows XML (Security/System/PowerShell/Defender/TaskScheduler/RDP), Sysmon (1–29), syslog RFC3164/5424 + sshd/sudo/su/useradd/UFW/cron/systemd/fail2ban, nginx/Apache access **and error** logs, journald & ECS JSON, Windows Firewall log, **auditd**, **Windows DHCP**, generic | `kharibulbul/pipeline/parsers/` |
| Schema | Kharibulbul Event Schema – flat ECS-style fields, guaranteed mandatory fields; **ECS-style normalisation**: `ecs.version`, categorisation fields mapped onto the ECS allowed values, validation after enrichment (tag `ecs-nonconformant`), nested ECS view (`?format=ecs`, ECS JSON export) | `kharibulbul/common/schema.py`, `kharibulbul/common/ecs.py`, `docs/SCHEMA.md` |
| Enrichment | network direction from lab ranges, **geo-IP enrichment** for every address (our CSV lab zones → optional MaxMind city database → DB-IP country table for the whole IPv4/IPv6 space, read by our own range index), asset inventory (role/owner/criticality → severity boost), local threat-intel lists | `kharibulbul/pipeline/`, `geoip/` |
| Store | SQLite + FTS5 with indexed hot columns, **no date limit** (retention off by default; search any period: quick ranges, `all`, exact from/to dates), alerts/agents/rule stats; **Kharibulbul query language** | `kharibulbul/store/` |
| Detection | YAML rules: selections+conditions (Sigma-like modifiers), thresholds (count / distinct per group), sequences, suppression; **95 rules** mapped to MITRE ATT&CK (18 written by the team in Week 3); **custom rules written in the dashboard** (validated, tested against pasted log lines, live at once) | `kharibulbul/detect/`, `rules/`, `custom/rules/` |
| Alerting | de-duplicated alerts with lifecycle (new → acknowledged → investigating → **escalated** → closed / false positive); **escalation** to the next tier with reason, severity raise and notification; console/file/webhook/SMTP notifiers | `kharibulbul/alerts/` |
| Presentation | FastAPI JSON API + dashboard written in vanilla JS with our own SVG charts (works offline): date-range search, **Add agent wizard** (config file + install guide) and agent IP addresses, rule editor, **playbook editor** | `kharibulbul/server/`, `kharibulbul/web/`, `custom/playbooks/` |
| Validation | **safe synthetic log generator** (52 scenarios) + hand-written samples + 123 tests + `rules coverage` matrix (94/95 rules exercised, baseline quiet) | `kharibulbul/simulate/`, `samples/`, `tests/`, `docs/reports/` |
| Operations | install scripts (Linux/Windows), Sysmon config, audit-policy script, certs, systemd/scheduled task, playbooks, ops guide | `scripts/`, `sysmon/`, `playbooks/`, `docs/` |

## Quick start (any laptop, 5 minutes)

```powershell
# Windows
.\scripts\run-dev.ps1              # venv + deps + rule validation + server on http://127.0.0.1:8080/
.\scripts\run-dev.ps1 -Simulate    # second window: 52 scenarios, 671 synthetic events -> alerts for 94 of 95 rules
.\scripts\run-dev.ps1 -Tests       # pytest
.\scripts\run-dev.ps1 -WindowsAgent   # Bülbül agent on this laptop (no admin rights needed)
.\scripts\run-dev.ps1 -WslSetup / -WslAgent / -WslActivity   # Linux agent inside WSL 2 (Ubuntu) + benign test activity
```
```bash
# Linux / macOS
bash scripts/run-dev.sh            # server
bash scripts/run-dev.sh simulate   # scenarios
bash scripts/run-dev.sh tests
```
Manual: `pip install -r requirements.txt && pip install -e .` then `kharibulbul server -c config/server.yml`.

Open **http://127.0.0.1:8080/** → Overview, Events, Alerts, Agents, Rules, Playbooks. API docs at `/api/docs` (no menu entry; open the address directly).
With `-WindowsAgent` and `-WslAgent` running, the *Agents* page shows a Windows host (`win-laptop`) and a Linux
host (`ubuntu-wsl`) online on the same laptop (`config/agent-windows-host.yml`, `config/agent-linux-wsl.yml`,
`scripts/wsl-agent.sh`).

## Lab deployment

See `docs/LAB-SETUP.md`: `scripts/install-server.sh` (Ubuntu), `scripts/install-agent.ps1`
(Windows: audit policy + Sysmon + agent as SYSTEM scheduled task), `scripts/install-agent.sh` (Linux),
`scripts/rsyslog-forward.conf` for appliances, `scripts/gen-certs.sh` for TLS.

## CLI

```
kharibulbul server -c config/server.yml       # ingest + detection + API + UI
kharibulbul agent  -c config/agent.yml        # Bülbül agent
kharibulbul rules validate | list | test <rule.yml> <log-or-jsonl> | coverage --out docs/reports/WEEK3-VALIDATION.md
kharibulbul simulate --list | <scenario…> | all [--out file.jsonl]
kharibulbul replay <file> --dataset linux.auth --host srv-web01
kharibulbul parse <file> --fields event.action,user.name     # parser debugging, no server needed (--ecs: nested ECS, --check: validate)
kharibulbul query "event.action:logon-failed AND source.ip:10.10.99.*" --since now-1h    # or --since all / --since 2026-09-01 --until 2026-09-15
kharibulbul alerts [--status new] | alerts ack|investigate|close|fp <id> --assignee <name>
kharibulbul alerts escalate <id> --to "SOC lead" --reason "root targeted"   # hand an alert to the next tier
kharibulbul geoip update | lookup <ip…> | status            # refresh the DB-IP country table / test the enrichment
kharibulbul stats
```

## In the dashboard

* **Any period** – quick ranges up to one year, *all*, or exact from/to dates on Overview, Events and Alerts.
* **Escalate** an alert (to whom, why, severity one step up) – every notifier is told.
* **Agents → ＋ Add agent** – name + system profile → configuration file and step-by-step install guide;
  the table shows every agent's IP addresses.
* **Rules → ＋ New rule** – write, validate, test and save your own YAML rule (`custom/rules/`).
* **Playbooks → ＋ New playbook** – Markdown editor with live preview (`custom/playbooks/`).
* **Events** – GeoIP country on source/destination, ECS version chip, nested ECS document and ECS JSON export.

GeoIP country data: *IP Geolocation by [DB-IP](https://db-ip.com)* (IP to Country Lite, CC BY 4.0).

## Documentation

* **`GUIDE.md`** – the complete guide (concepts, every component, configuration, API, rules, operations).
* `cloud.md` – project log: what was built, decisions, verification results (updated every session).
* `docs/reports/` – executed weekly reports (`WEEK1-REPORT`, `WEEK2-REPORT`, `WEEK3-VALIDATION` (generated matrix),
  `WEEK3-TABLETOP`, `WEEK4-REPORT`) and the `FINAL-REPORT` (v1.0); `docs/TUNING-LOG.md`, `docs/INCIDENTS.md`.
* `docs/ARCHITECTURE.md`, `docs/SCHEMA.md`, `docs/QUERY-LANGUAGE.md`, `docs/RULES.md`,
  `docs/OPERATIONS.md`, `docs/LAB-SETUP.md`, `dashboards/README.md`
* Weekly plan: `docs/WEEK1.md` … `docs/WEEK4.md`, `docs/TEAM-ROLES.md`, `docs/PRESENTATION.md`
* Response procedures: `playbooks/`

## Assignment mapping (B.5 Local Mini-SIEM)

| Requirement | Kharibulbul deliverable |
|-------------|-------------------------|
| Week 1 – install stack, deploy agents, enable Sysmon | server + agents + `sysmon/kharibulbul-sysmon.xml` + `scripts/enable-*.ps1`, `docs/WEEK1.md` |
| Week 2 – parsing, ECS-style normalisation, GeoIP | `pipeline/parsers`, `normalize.py`, `geoip.py`, `docs/SCHEMA.md`, `docs/WEEK2.md` |
| Week 3 – incident patterns (repeated failed logins, unusual process launches, scan-like connection patterns, LOLBins), alerts | `rules/` (95, incl. `rules/team/`), `simulate` (52 safe scenarios), `rules coverage` matrix, `alerts/`, `docs/WEEK3.md`, `docs/reports/WEEK3-*.md` |
| Week 4 – dashboards, playbooks, ops guide | web UI, `playbooks/`, `docs/OPERATIONS.md`, `docs/WEEK4.md` |
| Deliverables – dashboards, alert rules, lab scripts, procedure guide | `kharibulbul/web`, `rules/`, `scripts/`, `playbooks/` + `docs/` |

## Safety note

Detection testing uses **self-generated benign log records** (`kharibulbul simulate`) and hand-written
samples that *resemble* suspicious patterns. Nothing in this repository performs scanning, credential
testing or exploitation; the lab stays isolated and clean.

## License

MIT – see `LICENSE`.
