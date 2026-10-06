# Kharibulbul architecture

Kharibulbul is a from-scratch mini-SIEM. Wazuh, OpenSearch and Beats were studied as
*reference designs*; every component below is our own code (Python 3.10+, stdlib +
FastAPI/uvicorn/PyYAML), so the team can explain and change every line.

```
                 Windows hosts                          Linux hosts / appliances
   ┌────────────────────────────────┐        ┌────────────────────────────────────┐
   │ Sysmon + audit policy           │        │ auth.log · syslog · ufw.log · nginx │
   │ Bülbül agent (winlog input)     │        │ Bülbül agent (file/journald input)  │
   │  wevtutil → XML events          │        │ or rsyslog forwarding (UDP 5514)    │
   └──────────────┬─────────────────┘        └──────────────────┬─────────────────┘
                  │ TCP 5044 JSON lines (+TLS, acks, disk spool)  │
                  ▼                                               ▼
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │ Kharibulbul server (one Python process, asyncio)                              │
   │                                                                              │
   │  ingest/         TCP agent protocol · syslog UDP/TCP · HTTP POST /api/ingest │
   │      │  envelope {raw, dataset, host.name, @timestamp, fields}               │
   │      ▼                                                                       │
   │  pipeline/       parser registry ──► normalise ──► enrich                    │
   │     parsers: windows (XML) · sysmon · syslog+programs · web · json/journald  │
   │              · winfirewall · generic                                         │
   │     normalise: ECS-style flat fields, lower-casing, derived fields, hygiene  │
   │                ECS conform (ecs.version, allowed values) → validate after    │
   │     enrich:    direction (lab_networks) · GeoIP (zones csv + mmdb + country  │
   │                table) · assets.yml · threat intel lists · severity boost     │
   │      │  ECS document (flat dict)                                             │
   │      ├──────────────────────────────────────────┐                            │
   │      ▼                                          ▼                            │
   │  store/ SQLite + FTS5 (events, alerts,     detect/ rule engine               │
   │         agents, rule_stats)  ◄─────────────  match · threshold · sequence    │
   │         writer thread, batched, WAL              │ alert                     │
   │         query language → SQL                     ▼                           │
   │                                            alerts/ manager (dedupe, status)  │
   │                                                    notify: console · file    │
   │                                                    · webhook · SMTP          │
   │  api/ FastAPI: /api/events /alerts /agents /rules /dashboard /ingest         │
   │  web/ static dashboard (vanilla JS, own SVG charts)                          │
   │  optional: store/opensearch_store mirrors documents to OpenSearch            │
   └──────────────────────────────────────────────────────────────────────────────┘
                  ▲                                     ▲
        kharibulbul CLI (simulate, replay,       Analyst browser  http://server:8080/
        query, alerts, rules test, parse)
```

## Components and the Wazuh concepts they replace

| Wazuh / ELK concept | Kharibulbul component | File(s) |
|---------------------|-----------------------|---------|
| wazuh-agent / Winlogbeat / Filebeat | **Bülbül agent** – inputs: `file`, `winlog`, `journald`, `command`; batching, acks, reconnect with back-off, disk spool | `kharibulbul/agent/` |
| wazuh-remoted (agent protocol) | TCP newline-JSON protocol with `hello/batch/ack/heartbeat`, optional TLS/mTLS, shared secret | `server/ingest.py` |
| syslog collector | UDP/TCP syslog listener | `server/ingest.py` |
| decoders | parser registry (Windows XML, Sysmon, syslog+program parsers, web, JSON/journald, Windows Firewall, generic) | `pipeline/parsers/` |
| ECS / Wazuh field schema | **Kharibulbul Event Schema** – flat ECS-style dotted keys, `finalize()` guarantees mandatory fields, `ecs.py` maps categorisation values onto ECS, validates every event and serves the nested ECS view | `common/schema.py`, `common/ecs.py`, `pipeline/normalize.py` |
| GeoIP / CDB lists | GeoIP (custom CSV zones → MaxMind city db → DB-IP country table read by our own range index), asset inventory, threat-intel lists | `pipeline/geoip.py`, `countries.py`, `assets.py`, `intel.py` |
| agent enrolment (`manage_agents`) | *Add agent* wizard: issues the agent id, generates the agent YAML and the install guide, lists the agent as pending | `server/enroll.py`, `server/api.py` |
| custom rules / decoders in `etc/rules` | custom rules and playbooks written from the dashboard, kept apart from the shipped ones | `server/content.py`, `custom/` |
| OpenSearch index | SQLite + FTS5 store with indexed hot columns and a query language | `store/sqlite_store.py`, `store/query.py` |
| Wazuh rules XML / Sigma | YAML rules: selections + condition, thresholds (count/distinct per group), sequences, suppression | `detect/` |
| wazuh-analysisd | streaming `DetectionEngine.evaluate(doc)` per event | `detect/engine.py` |
| alerts.json + integrations | AlertManager (dedupe per rule+entity, status workflow) + notifier sinks | `alerts/` |
| Wazuh API / Dashboards | FastAPI + our own single-page dashboard | `server/api.py`, `web/static/` |
| wazuh-control / CLI | `kharibulbul` CLI: server, agent, rules validate/test, simulate, replay, parse, query, alerts | `cli.py` |

## Data flow of one event

1. **Collect** – the agent tails a file or polls `wevtutil` and creates an *envelope*:
   `{"raw": "<Event…>", "dataset": "windows.security", "@timestamp": "…", "host.name": "ws01", "fields": {...}}`.
2. **Ship** – envelopes are batched (100 / 1 s), sent as one JSON line, acknowledged by the server.
   No ack → batch goes to the disk spool and is replayed after reconnect.
3. **Parse** – `Pipeline.select_parsers()` picks candidates from the dataset hint and the first bytes of `raw`;
   the first parser that returns a document wins; `generic` never fails.
4. **Normalise** – consistent casing, `process.args`, `related.ip/user`, DNS registered domain and
   suspicious-TLD tag, numeric ports, mandatory fields (`event.id`, `event.kind`, `event.severity` …).
5. **Enrich** – `network.direction` from lab networks, GeoIP for both sides, host role/owner/criticality,
   threat-intel match (`threat.indicator.*`, tag `threat-intel-match`), severity boost.
6. **Store** – queued to the writer thread; hot fields go into real columns, the full document into JSON,
   text fields into FTS5.
7. **Detect** – every enabled rule is evaluated against the document (cheap `logsource` pre-filter first).
   Threshold and sequence rules keep in-memory state keyed by `group_by`/`by` values and use *event* time.
8. **Alert** – the AlertManager checks for an open alert with the same rule + entity inside the suppress
   window (update count) or creates a new one; notifiers run in a background thread. An analyst can
   **escalate** an alert to the next tier (status `escalated`, level, severity one step up, notification).
9. **Present** – the API serves search/aggregations/alerts; the dashboard polls it.

## Threading / concurrency model

* asyncio event loop: sockets, HTTP API.
* `handle_batch()` (parse → store → detect) runs in the default thread-pool executor so the loop stays responsive.
* Store writer thread batches inserts (SQLite WAL, `synchronous=NORMAL`); readers use thread-local connections.
* Detection engine and alert manager are guarded by re-entrant locks (multiple executor threads).
* Notifier thread isolates slow webhooks/SMTP.

Measured on a laptop: ~2–4k events/s through the full pipeline with 95 rules, which is far above what a
4-host lab produces (tens of events/s).

## Security model (lab)

* Agents authenticate with an optional shared secret and/or mutual TLS (`scripts/gen-certs.sh`).
* The API can require a bearer token (`api.token`); the UI stores it in the browser.
* The server never executes anything from log content; parsers are pure string processing; a parser
  exception is caught and tagged (`parser-error`) instead of crashing ingest.
* Retention is off by default (`store.retention_days: 0`, no date limit); when set, old events are purged
  hourly and alerts survive until closed + retention.
* Content written from the dashboard (rules, playbooks) is validated, size-limited, restricted to safe
  file names inside `custom/`, and can never overwrite shipped content; playbook Markdown is rendered
  with HTML escaped and only http(s) / relative links.

## Extending

* **New log source**: add `pipeline/parsers/<name>.py` with `@register("<name>")`, import it in
  `parsers/__init__.py`, add it to `Pipeline.select_parsers()` for its dataset, add a test.
* **New rule**: drop a YAML file under `rules/`, run `kharibulbul rules validate`, test it with
  `kharibulbul rules test <file> <sample>` or `POST /api/rules/test`, then `POST /api/rules/reload`.
* **New notifier**: add a method to `alerts/notify.py` and a config block under `alerts.notify`.
* **New dashboard panel**: add a store aggregation, expose it in `/api/dashboard/overview`, render it in `app.js`.
