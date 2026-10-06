# Operations guide (SOC runbook for the Kharibulbul lab)

## Daily routine (on-duty analyst)

| When | What | How |
|------|------|-----|
| Start of shift | Check SIEM health | Overview page footer (uptime), `kharibulbul stats`, Agents page: every host `online` |
| Start of shift | Review new alerts | Alerts page, filter *open*; acknowledge what you take (`assignee`) |
| Continuous | Triage per playbook | `playbooks/` – the alert drawer links the right one |
| Hourly | Data quality | `tags:parser-error` in the last hour should be empty; KB-KB-002 alerts |
| End of shift | Hand-over | close or annotate every alert you touched; note tuning ideas in `docs/TUNING-LOG.md` |
| Weekly | Rule review | Rules page: rules with 0 hits (dead) vs. noisy rules; tune filters; validate & reload |
| Weekly | Disk | DB size on the Overview card (retention is off by default: `store.retention_days: 0`) |
| Monthly | GeoIP table | `kharibulbul geoip update`, restart the server |

## Start / stop

| Component | Windows (dev/demo) | Linux (service) |
|-----------|--------------------|-----------------|
| Server | `.\scripts\run-dev.ps1` | `systemctl start|stop|status kharibulbul-server`, logs: `journalctl -u kharibulbul-server -f` |
| Agent | `.\scripts\run-dev.ps1 -Agent` or scheduled task *Kharibulbul Agent* | `systemctl start kharibulbul-agent` |
| Tests | `.\scripts\run-dev.ps1 -Tests` | `bash scripts/run-dev.sh tests` |

Ports: 5044/tcp agents, 5514/udp syslog, 8080/tcp UI + API. Change them in `config/server.yml`.

## Configuration changes

* `config/server.yml` – restart the server after editing (except rules and intel lists).
* `rules/` – `kharibulbul rules validate rules` then `POST /api/rules/reload` (Rules page button).
* `custom/rules/`, `custom/playbooks/` – written by the dashboard, active at once (hand edits: *reload from disk*).
* `intel/*.txt` – picked up automatically within 30 s.
* `config/assets.yml`, `geoip/custom_ranges.csv` – restart the server.
* Agents – edit `config/agent*.yml`, restart the agent.

Secrets: set `KB_API_TOKEN` and `KB_SHARED_SECRET` in the environment (systemd `EnvironmentFile`)
rather than in the YAML; the config expands `${KB_API_TOKEN:-}`.

## Backup

* Events + alerts: `data/kharibulbul.db` (SQLite, WAL). Hot backup:
  `sqlite3 data/kharibulbul.db ".backup backups/kb-$(date +%F).db"` (Linux) or stop the server and copy.
* Alerts also stream to `data/alerts.jsonl` (append-only) – keep it with the report evidence.
* Configuration, rules, playbooks, intel – in git.

## Retention

`store.retention_days` is **0 by default: nothing is purged**, so an investigation can go back as far
as the data does (Events page: quick ranges up to one year, *all*, or exact from/to dates). Watch the
database size on the Overview card; when disk becomes a concern set `retention_days: N` — a background
task then purges events older than N days (and closed alerts) every hour. To free disk after a purge:
`sqlite3 data/kharibulbul.db "VACUUM;"` (server stopped).

## Escalation

An analyst who cannot resolve an alert presses **⬆ Escalate** in the alert drawer (or
`kharibulbul alerts escalate <id> --to … --reason …`): the alert becomes `escalated`, level 1 → 2 → 3
(*Tier 2 analyst* → *SOC lead / incident responder* → *Incident manager (CSIRT)* unless a name is
given), the severity goes one step up and every enabled notifier is told. The receiving tier filters
the Alerts page by status `escalated`, takes the alert (assignee) and continues with the playbook.

## Adding a host

Agents page → **＋ Add agent**: name, system profile, server address. Save the generated
`agent-<name>.yml` on the host, follow the steps shown (they are specific to the chosen system) and
the pending row turns `online`. Remove a decommissioned host with ✕.

## Custom rules and playbooks

Rules page → **＋ New rule** (validate & test against pasted log lines before saving), Playbooks page →
**＋ New playbook**. Both are stored under `custom/` and should be committed like the shipped content.
Record the reason for every new or changed rule in `docs/TUNING-LOG.md`.

## GeoIP table

`kharibulbul geoip update` once a month (needs internet on the machine that runs it; copy
`geoip/dbip-country-lite.csv.gz` to an offline server), then restart the server.

## Health signals and what they mean

| Signal | Where | Action |
|--------|-------|--------|
| Agent `silent` / KB-KB-001 | Agents page / alert | host off? agent task stopped? network? see PB-005 |
| `ingest.rejected` growing | `/api/stats` | wrong shared secret or malformed sender |
| `store.queued` growing | `/api/stats` | disk slow / DB locked – check free space, WAL size |
| `pipeline.dropped_unparsed` | `/api/stats` | empty lines only (generic parser accepts anything else) |
| `detect.errors` non-empty | `/api/stats` | a rule with a bad regex – fix and reload |
| `notification_failures` | `/api/stats` | webhook/SMTP unreachable |

## Troubleshooting

**Agent cannot connect** – `Test-NetConnection <server> -Port 5044`; check `ingest.tcp.host`;
firewall (`ufw status`); shared secret mismatch shows `bad shared secret` in the server log.

**Windows agent shows 0 events** – must run elevated (Security log). Check
`wevtutil qe Security /c:1 /rd:true` manually. Bookmarks are in `data/agent-state/winlog-*.json`;
delete to re-read from the latest record.

**No Sysmon events** – `Get-Service Sysmon64`; reinstall with `scripts/enable-sysmon.ps1`.

**Linux agent, no auth events** – Ubuntu ≥ 22.10 minimal images may not have `rsyslog`; enable the
`journald` input in `config/agent.yml` or `apt install rsyslog`.

**Time is wrong on the dashboard** – hosts must be NTP-synced; the engine uses event time, so a host
5 minutes in the future breaks threshold windows. `w32tm /resync`, `timedatectl`.

**Rule does not fire** – `kharibulbul parse` the event and compare field names with the rule;
remember `event.code` is a string and `process.name` is lower-case; check `logsource` (Sysmon = dataset
`windows.sysmon`, module `windows`).

**UI says unauthorized** – set the token via the *API token* link in the sidebar.

**Database locked** – only one server process may write; check for a second instance
(`Get-Process python`).

## Incident log

Keep `docs/INCIDENTS.md` (create on first incident): date, alert ids, summary, actions,
lessons learned, rule changes. The final report uses it.

## Change management for rules (proposed for the team)

1. Branch → edit rule → `kharibulbul rules validate` → `pytest` → PR with a sample or simulate scenario.
2. Reviewer checks false-positive section and playbook link.
3. Merge → `git pull` on the server → `POST /api/rules/reload`.
