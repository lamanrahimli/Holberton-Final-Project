# Week 3 — tabletop exercise and alerting verification

*Executed 2026-09-27 against a freshly started server (clean database) with the CLI as the
analyst console. All activity is synthetic log data from `kharibulbul simulate`.*

## 1. Injection

`kharibulbul simulate baseline windows-brute-force lolbin rdp-then-service` → 98 events stored.
Baseline (72 benign events) produced no alerts; the three attack-pattern scenarios produced 13:

| # | Severity | Rule | Entity | Count |
|---|----------|------|--------|------:|
| 1 | critical | KB-COR-001 brute force → success | source.ip=10.10.20.55 | 16 |
| 2 | high | KB-WIN-001 brute force | ws01 / 10.10.20.55 | 10 |
| 3 | critical | KB-COR-006 RDP → service install | ws01 | 4 |
| 4 | high | KB-WIN-030 service from suspicious path | ws01 / KBRemoteSvc | 1 |
| 5 | low | KB-WIN-031 service inventory | ws01 / KBRemoteSvc | 1 |
| 6–13 | high/medium | KB-SYS-010…016, 018 LOLBins | ws01 / aysel | 1 each |

## 2. Analyst actions (CLI, timestamps from the alert history)

| Alert | Action | Analyst | Time after creation |
|-------|--------|---------|--------------------:|
| KB-COR-001 | `alerts ack` — "failures then success from 10.10.20.55 (Lab-Workstations); PB-001 triage started" | aysel | 4.3 s |
| KB-COR-001 | `alerts investigate` — "account aysel, logon type network; host isolated in hypervisor, password reset, source blocked at host firewall" | aysel | 4.4 s |
| KB-COR-001 | `alerts close` — "synthetic exercise, all PB-001 steps executed, evidence exported" | aysel | 4.5 s |
| KB-COR-006 | `alerts ack` + `investigate` — "RDP then service KBRemoteSvc from C:\Windows\Temp; service disabled, binary quarantined and hashed, host isolated" (PB-008) | rauf | ~5 s |
| KB-SYS-010 | `alerts fp` — "certutil download is the exercise generator (fields.simulation=lolbin)" | leyla | ~5 s |

Resulting summary (`GET /api/alerts/summary`): total 13 — closed 1, false_positive 1,
investigating 1, new 10; open 12. History of the closed alert:
`new by kharibulbul → acknowledged by aysel → investigating by aysel → closed by aysel`
(every transition timestamped and carrying the notes). `data/alerts.jsonl` received 13 lines.

Time-to-acknowledge in the exercise: < 5 s (scripted); the real target from `docs/OPERATIONS.md`
is 15 min for high and 5 min for critical.

## 3. Notification verification (webhook)

Profile `config/server-webhook-test.yml` (webhook `min_severity: high`) + a local HTTP receiver:

* scenarios `windows-brute-force log-cleared web-scan` → 7 alerts
  (critical 1, high 4, medium 2)
* receiver got **5 POSTs** = exactly the high/critical ones (KB-WIN-001, KB-COR-001, KB-WIN-020, KB-WEB-004, KB-WEB-002); the two medium alerts were correctly filtered
* payload: `{"source": "kharibulbul", "alert": {...}, "text": "[HIGH] <rule>: <summary>"}` with the
  custom header `X-Kharibulbul-Test: week3`; server counters `webhook: 5, failures: 0`

SMTP was not exercised (no mail server in the lab); the sink is implemented and configured the
same way (`alerts.notify.smtp`).

## 4. Playbook walk-through findings

* Every triage query in the nine playbooks compiles (`tests/test_playbooks.py`, 40+ queries);
  the `field:(a OR b)` grouping used by several playbooks was added to the query language in Week 4.
* Every rule now links to a playbook (7 rules were missing one — fixed) and every rule id cited
  in the playbooks exists.
* Observed while triaging: the KB-COR-006 alert shows *count 4* because the sequence track keeps
  all stage-1 matches (baseline RDP-type logons on the same host) as evidence — acceptable, but the
  playbook now tells the analyst to read `sample_events` for the actual chain.

## 5. Validation matrix

See `WEEK3-VALIDATION.md` (generated): **94 / 95 rules** fired by at least one of the 52 scenarios,
baseline quiet. The only rule without a scenario is KB-KB-002 (parser-error burst): the tag
`parser-error` is only set when a parser raises an exception, which no well-formed input does, so it
is deliberately not simulated (it is a data-quality alarm for the SOC engineers, not a detection).
