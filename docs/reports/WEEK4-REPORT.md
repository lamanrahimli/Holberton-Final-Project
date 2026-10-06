# Week 4 report — dashboards, playbooks, operations, hardening

*Executed 2026-09-27. Evidence: test suite (98 tests), live TLS run, dashboard code, docs.*

## 1. Dashboards

Three panels were added to the built-in Overview page (store aggregation → `/api/dashboard/overview` → `app.js`):

| Panel | Backing data | Purpose (SOC question) |
|-------|--------------|------------------------|
| Authentication success vs failure over time | two histograms (`event.category:authentication AND event.outcome:success/failure`) drawn with a new multi-line SVG chart | "Are we being brute-forced right now?" |
| Open alerts by ATT&CK tactic | `SQLiteStore.alert_tactics()` — `json_each` over each alert's `mitre` list, open alerts only | "Which phase of an attack are we seeing?" |
| Events by asset criticality | `terms(kharibulbul.asset.criticality)` | "Is the noise on critical assets?" |

Existing pages (Overview, Events, Alerts, Agents, Rules, Playbooks) were reviewed against the SOC
question list in `docs/WEEK4.md`; the query language gained `field:(a OR b OR c)` grouping because
several playbook queries needed it. Branding check: title, logo, flag palette, `Salam!` greeting.

## 2. Playbooks

* Nine playbooks; triage blocks are ```` ```kql ```` fences so `tests/test_playbooks.py` compiles
  every query (40+) and verifies every cited rule id exists — playbooks cannot silently rot.
* Every one of the 95 rules links to a playbook (7 gaps found by the test and fixed).
* The index (`playbooks/README.md`) lists the Week 3 team rules per playbook.

## 3. Operations guide

* `docs/OPERATIONS.md` (routine, start/stop, config changes, backup, retention, health signals,
  troubleshooting, change management), now accompanied by real `docs/TUNING-LOG.md` (15 entries)
  and `docs/INCIDENTS.md` (3 exercised incidents).
* Fresh-install substitute on the dev PC: all install/ops scripts pass syntax validation
  (`bash -n` for 4 shell scripts, PowerShell parser for 5 scripts); the Sysmon XML parses
  (schema 4.90, 17 rule groups). Executing the installers requires the lab VMs.

## 4. Hardening — verified live

| Control | Test | Result |
|---------|------|--------|
| TLS on the agent port | `config/server-tls-test.yml` (cert/key from `scripts/gen-certs.sh`) | agent logged `connected … (tls=True)`; event delivered; agent `online` |
| Mutual TLS | server `tls.ca` set → client certificate required; agent presents `certs/agent-laptop-test.crt` | accepted (registered from 127.0.0.1) |
| Shared secret | agent started with `KB_TLS_SECRET=wrong-secret` | server: `rejected: bad shared secret` (3 attempts), agent: `server rejected hello` |
| API token | `api.token` set in the API test profile | 401 without token, 200 with `Authorization: Bearer` / `X-API-Key` (`tests/test_api.py`) |
| Path safety | `GET /api/playbooks/../secret.md` | 404 (basename only) |
| Server-side path resolution | TLS cert paths relative to the repo | resolved in `server/main.py` regardless of the working directory |

Remaining hardening for the lab VMs (documented, not executable on the dev PC): UFW rules from
`install-server.sh`, systemd sandboxing in `kharibulbul-server.service`, agent as SYSTEM task.

## 5. Report & defence material

* `docs/reports/FINAL-REPORT.md` — full report draft with the measured numbers.
* `docs/PRESENTATION.md` — slide outline; `docs/WEEK4.md` — 15-minute demo script and likely questions.
* `GUIDE.md` — complete reference; `cloud.md` — project log with both sessions.

## 6. Checklist status (from `docs/WEEK4.md`)

- [x] dashboard panel added (three) · [x] branding · [x] playbooks walked (queries tested) · [x] ops guide + logs
- [x] hardening (TLS/mTLS/secret/token) verified · [x] report draft · [x] demo script
- [ ] screenshots with real lab data · [ ] fresh-install on a reverted VM · [ ] git tag `v1.0` (team)
