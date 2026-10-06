# Week 3 · Detection rules, safe validation, alerting

**Goal:** a tuned rule set that fires on the suspicious patterns from the assignment (repeated failed
logins, unusual process launches, network-scan-style connection patterns, living-off-the-land
binaries) and stays quiet on normal lab traffic. All validation uses **self-generated benign test
log samples**, never real attack tooling against the lab.

## Deliverables
* Rule set reviewed: every rule has description, MITRE mapping, playbook link, false-positive notes
  (`kharibulbul rules validate` = 0 problems; `pytest tests/test_rules.py`).
* **≥5 rules written by the team** on top of the shipped 77 (ideas below).
* Validation matrix: scenario → expected rules → result (from `tests/test_pipeline_e2e.py` +
  manual runs), plus a *baseline noise* measurement (alerts per hour on normal traffic).
* Alert notification working to at least one external sink (webhook to a Discord/Slack/Teams
  test channel, or SMTP to a lab mailbox).
* Detection engineering write-up for the report (how thresholds, sequences and suppression work).

## Day-by-day

| Day | Task | Done when |
|-----|------|-----------|
| Mon | Run every scenario: `kharibulbul simulate all`; review each alert in the UI with its playbook | validation matrix filled |
| Mon | Baseline noise: 2 h of normal use + `simulate baseline`; list rules that fired | noisy rules identified |
| Tue | Tune: add `filter_*` selections / raise thresholds / adjust `suppress`; document in the rule | baseline alerts/hour ≤ 2 |
| Tue | Write 2 new rules (see ideas), test offline (`rules test`), add scenario or sample | tests green |
| Wed | Write 3 more rules incl. one **sequence** rule; test | tests green |
| Wed | Alerting: enable webhook (`alerts.notify.webhook`) with `min_severity: high`; verify a critical alert arrives | screenshot for report |
| Thu | Tabletop: one member plays analyst, another injects scenarios (`simulate --host ws02 --source-ip 10.10.99.20`); measure time-to-acknowledge; run the playbook | notes for the ops guide |
| Thu | Threat intel exercise: add 3 indicators, generate matching synthetic events, confirm KB-TI-* and severity boost | – |
| Fri | Regression: `pytest`, `rules validate`; freeze rules v1.0 (git tag); snapshot "rules tuned" | – |
| Fri | Write Week 3 in `cloud.md` | – |

## Safe validation approach (say this in the defence)

* `kharibulbul simulate` writes **log records** that look like the suspicious activity
  (Windows XML, Sysmon, syslog, nginx lines) and posts them to `/api/ingest`. No process is started,
  no port is touched, no credential is tried. The whole server path (parse → enrich → detect → alert
  → notify → dashboard) is exercised exactly as with real logs.
* `samples/*.log` are hand-written realistic excerpts for replay.
* Unit tests assert that each scenario fires the expected rules and that baseline traffic fires none
  (`tests/test_pipeline_e2e.py`).
* Live traffic from the lab hosts provides the *normal* side for false-positive tuning.

## Rule ideas for the team (pick 5+)

| Idea | Kind | Fields |
|------|------|--------|
| Logon outside working hours on the DC | match (needs a small `hour_of_day` field – add it in `normalize.py`!) | `event.action:logon-success`, new field |
| Same user logging on from two hosts within 2 min | threshold distinct `host.name` by `user.name` | 4624 |
| RDP session followed by service install | sequence by `host.name` | `rdp-logon-success` → `service-installed` |
| New scheduled task by non-admin user | match + filter on admin list | 4698 |
| Firewall block burst from internal host to internet | threshold by `source.ip` | `linux.firewall` outbound |
| Web 5xx spike (availability) | threshold count 20 in 1 m | `http.response.status_code:>=500` |
| sudo by a user not in the admin list | match + filter | `sudo-command` |
| Sysmon 11 executable dropped in Downloads then executed | sequence | `file-created` → `process-created` |
| DNS query burst to a single registered domain (beacon) | threshold count by `dns.question.registered_domain` | Sysmon 22 |
| Defender exclusion added (registry) | match | Sysmon 13 `\Exclusions\` |

## Tuning log template (`docs/TUNING-LOG.md`)
```
date | rule | symptom (alerts/hour, example entity) | change (filter/threshold/suppress) | result
```

## Verification checklist
- [ ] `kharibulbul simulate all` → every EXPECTED rule in `tests/test_pipeline_e2e.py` fires
- [ ] `kharibulbul simulate baseline` → 0 alerts
- [ ] Every alert opens a playbook from the drawer
- [ ] Webhook/SMTP notification screenshot
- [ ] `git tag rules-v1.0`
