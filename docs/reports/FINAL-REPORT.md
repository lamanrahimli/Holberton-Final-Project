# Kharibulbul (Xarıbülbül) SIEM — Final project report (v1.0)

*Assignment B.5 "Local Mini-SIEM". Team of 3–4 students, one month. All numbers in this report were
measured on 2026-09-27 from the repository state described in `cloud.md`; screenshots with real lab
data are to be added by the team after the VM deployment (Week 1 checklist).*

---

## 1. Introduction and objectives

The assignment asked for a home SOC stack built from free components — install Wazuh, OpenSearch,
Beats and Sysmon, ingest logs, build detections. Our professor rejected that scope: anyone can
download and configure Wazuh. The revised objective was to **design and build our own SIEM from
scratch**, using the listed products only as reference designs, and to give it a national identity.

Objectives:
1. Centralise logs from Windows and Linux lab hosts with our own agent and transport.
2. Parse and normalise them into one consistent, ECS-compatible schema; enrich with GeoIP, asset and
   threat-intelligence context.
3. Detect the incident patterns named in the assignment — repeated failed logins, unusual process
   launches, scan-like connection patterns, living-off-the-land binaries — and raise actionable alerts.
4. Validate detections safely (synthetic benign log samples), inside an isolated lab.
5. Deliver dashboards, alert rules, lab scripts and a procedure guide.

The result is **Kharibulbul**, named after the Khari Bulbul orchid of Shusha whose lip looks like a
nightingale (*bülbül*) sitting in the flower — the SIEM sits in the network and listens.

## 2. Related work and reference designs

* **Wazuh** — agent/manager model, decoders → rules → alerts pipeline, frequency rules, agent
  protocol with keys. We borrowed the model and simplified the implementation (§ 13).
* **OpenSearch / Elastic** — the Elastic Common Schema field names, index templates, dashboards.
  We adopted ECS naming and provide an optional OpenSearch mirror.
* **Sigma** — the selection/condition rule language and modifiers (`|contains`, `|re` …).
* **Sysmon** (Sysinternals) and the public SwiftOnSecurity configuration — the only external
  component we run on hosts; our configuration is our own (17 rule groups).

## 3. Architecture

One Python process (asyncio) per SIEM server; a Python agent per host.

```
hosts ── Bülbül agent (file / winlog / journald / command) ──TCP+TLS──► ingest ──► pipeline ──► store (SQLite+FTS5)
appliances ── syslog UDP/TCP ────────────────────────────────────────►          └──► detection engine ──► alerts ──► notifiers
CLI / scripts ── HTTP POST /api/ingest ─────────────────────────────►                                        └──► API ──► dashboard
```

Components (`docs/ARCHITECTURE.md`): agent (`kharibulbul/agent`, 4 inputs, acks, back-off, disk
spool), ingest listeners (`server/ingest.py`), parser registry (10 parsers), normaliser, enrichers
(direction, GeoIP, assets, intel, time context), SQLite+FTS5 store with a query language, streaming
rule engine (match / threshold / sequence), alert manager and notifiers, FastAPI API, vanilla-JS
dashboard with self-written SVG charts, CLI, synthetic scenario generator.

Size: ≈7,000 lines of Python, 640 lines of HTML/CSS/JS, 95 YAML rules (≈2,000 lines), 98 tests,
9 playbooks, 12 scripts, 24 documentation files.

## 4. Collection (Week 1)

* **Agent inputs**: file tail (rotation and truncation safe, offsets persisted), Windows Event Log
  via `wevtutil` with per-channel bookmarks and noise exclusions, journald, periodic commands.
* **Transport**: newline-JSON over TCP; `hello` (agent identity + shared secret) → `welcome`;
  `batch` → `ack`; `heartbeat` → `pong`. Optional TLS with lab CA and mutual TLS.
* **Reliability**: verified by killing the server during collection — 10 events spooled to disk and
  replayed in order after restart, spool empty afterwards, no loss (`WEEK1-REPORT.md`). A file-input
  identity bug on Windows was found by this test and fixed.
* **Windows telemetry**: `scripts/enable-audit-policy.ps1` (logon, account, policy, process creation
  with command line, PowerShell script-block logging, firewall drop log, larger logs) and
  `scripts/enable-sysmon.ps1` with `sysmon/kharibulbul-sysmon.xml`.
* **Linux telemetry**: auth.log/secure, syslog, UFW, nginx/Apache access and error logs, auditd,
  fail2ban; or rsyslog forwarding for appliances.
* Deployment scripts: `install-server.sh` (systemd, UFW), `install-agent.sh`, `install-agent.ps1`
  (scheduled task as SYSTEM), `gen-certs.sh`. All syntax-checked; executed on the dev PC where possible.

## 5. Parsing and schema (Week 2)

* **Kharibulbul Event Schema** (`docs/SCHEMA.md`): flat documents with dotted ECS keys; mandatory
  fields guaranteed by `finalize()`; provider codes as strings; lower-case names; unknown fields kept.
* **Parsers**: Windows XML (Security 30+ event ids, System, PowerShell 4104/4103, Defender,
  TaskScheduler, RDP), Sysmon 1–29, syslog RFC3164/5424 with sshd/sudo/su/user management/UFW/cron/
  systemd/logind/fail2ban sub-parsers, nginx/Apache access, nginx/Apache error, journald and ECS JSON,
  Windows Firewall log, auditd, Windows DHCP, generic fallback.
* **Selection**: dataset hint from the shipper plus content sniffing; the first parser that returns
  a document wins; parser exceptions are tagged, never fatal.
* **Coverage** (`WEEK2-REPORT.md`): 100 % of real log rows in `samples/` reach a specific parser;
  89.5 % even without a dataset hint; 671 synthetic events of 52 scenarios: 100 % parsed, 0 errors.

## 6. Enrichment (Week 2)

Direction relative to `pipeline.lab_networks`; GeoIP from our own CSV of lab zones (offline) with
MaxMind GeoLite2 as an optional second source; asset inventory (`config/assets.yml`: role, owner,
criticality → severity boost); local threat-intelligence lists (IP/CIDR, domain, hash) with hot
reload; time context (`kharibulbul.time.hour/weekday/business_hours`, lab timezone UTC+4).

## 7. Storage and query (Weeks 2–4)

SQLite in WAL mode with FTS5; hot fields as indexed columns, full document as JSON; single writer
thread; thread-local readers; retention purge. Query language: `field:value`, wildcards, numeric
comparisons, `field:(a OR b)`, list fields, full-text, boolean logic (`docs/QUERY-LANGUAGE.md`).
Optional write-only OpenSearch mirror with an ECS index template.

## 8. Detection engine and rule set (Week 3)

* **Rules**: YAML, Sigma-like selections with 12 modifiers, conditions (`1 of sel_*` …), thresholds
  (count or distinct values per `group_by` inside a sliding window), sequences (ordered stages per key
  within a window), suppression, per-entity alerting, MITRE ATT&CK mapping, playbook link.
* **Engine**: every event is evaluated against every enabled rule after a cheap `logsource`
  pre-filter; state is keyed by entity and uses *event* time; garbage-collected; errors in one rule
  never stop the others; rules can be toggled and reloaded live.
* **Rule set**: 95 rules in 10 families — Windows authentication/IAM/defense-evasion/persistence,
  LOLBins, PowerShell, process behaviour, registry, network scans and DNS, Linux authentication and
  privilege, web, threat intel, correlation, SIEM health — of which 18 were written in Week 3 as the
  team's own contribution (`rules/team/`), covering out-of-hours access to critical assets, account
  hopping, RDP-then-service, download-then-execute, Defender exclusions, DNS beacons, fail2ban,
  DHCP anomalies, auditd, availability.

## 9. Validation methodology and results (Week 3)

* **Safety**: no scanning, credential testing or exploitation in the lab. `kharibulbul simulate`
  writes log *records* (Windows XML, Sysmon, syslog, web) that resemble the suspicious patterns and
  posts them to the ingest API; the entire server path is exercised exactly as with real logs.
* **Matrix** (`WEEK3-VALIDATION.md`, generated by `kharibulbul rules coverage`): 52 scenarios,
  671 events → **94 / 95 rules fire**; the `baseline` scenario (72 benign events) fires **0 rules**.
* **Tests**: 98 pytest tests — parsers (25), query/store (5), rule semantics (9), end-to-end
  scenario expectations (55), API (3), playbooks (3) — all passing.
* **Tabletop** (`WEEK3-TABLETOP.md`): 13 alerts triaged through the CLI with assignees and notes;
  lifecycle history recorded; webhook delivery verified (5 of 7 alerts forwarded by severity).

## 10. Alerting, playbooks and operations (Weeks 3–4)

Alert lifecycle `new → acknowledged → investigating → closed | false_positive`, de-duplication per
rule + entity, sample events, MITRE tags; sinks: console, JSONL file, webhook (verified), SMTP.
Nine playbooks with tested triage queries; `docs/OPERATIONS.md` runbook; `docs/TUNING-LOG.md`
(15 entries) and `docs/INCIDENTS.md` (3 exercised incidents).

## 11. Dashboards (Week 4)

Built-in single-page dashboard: Overview (KPIs, events and alerts over time, severity donut, top
hosts/actions/IPs/datasets/users/countries/processes, recent alerts, alerts by rule, **authentication
success vs failure**, **open alerts by ATT&CK tactic**, **events by asset criticality**), Events
(query, facets, drawer, export), Alerts (triage), Agents, Rules (toggle/reload/YAML), Playbooks.
No build step, no CDN — works in the isolated lab. OpenSearch Dashboards can be attached to the mirror.

## 12. Security of the SIEM itself (Week 4)

Shared secret and TLS/mutual TLS for agents (verified live: correct certificate + secret accepted,
wrong secret rejected), API bearer token (tested), no execution of log content, parser isolation,
path-safe playbook endpoint, systemd sandboxing, UFW rules limited to lab ranges, retention.

## 13. Evaluation, comparison with Wazuh, limits

| Aspect | Wazuh (reference) | Kharibulbul |
|--------|-------------------|-------------|
| Agent | C, many modules (FIM, SCA, rootcheck) | Python, 4 inputs, spool + acks |
| Decoding / rules | XML decoders and rules | Python parsers, YAML Sigma-like rules with thresholds/sequences |
| Storage | OpenSearch cluster | SQLite + FTS5 single file; OpenSearch optional |
| Size | 100k+ lines | ≈7k lines — every layer explainable by the team |
| Not implemented | – | FIM, vulnerability detection, SCA, active response, HA |

Throughput on a laptop: thousands of events per second through the full pipeline with 95 rules;
lab volume is tens per second. Limits: single node, polling Windows collection (≈2 s latency), no
statistical baselining, single API token, GeoIP for public IPs needs the MaxMind file.

## 14. Team and process

Roles and weekly rhythm in `docs/TEAM-ROLES.md`; the four weekly plans in `docs/WEEK1-4.md` with
their execution reports in `docs/reports/`; the running project log in `cloud.md`.

## Appendices

* A. Rule catalogue — `kharibulbul rules list` (95 rules) and `docs/RULES.md`.
* B. Scenario list — `kharibulbul simulate --list` (52 scenarios).
* C. Schema — `docs/SCHEMA.md`, `GET /api/schema`.
* D. Scripts — `scripts/` (9 files) + `sysmon/kharibulbul-sysmon.xml`.
* E. Evidence — `docs/reports/*.md`, `data/alerts.jsonl` excerpts, `pytest` and `rules validate` output.
