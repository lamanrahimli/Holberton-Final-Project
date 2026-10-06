# Week 4 · Dashboards, playbooks, operations guide, defence

**Goal:** the SIEM is presentable and operable by someone who did not build it: dashboards answer
the SOC questions, playbooks guide every alert, the ops guide keeps it running, and the team can
defend every design decision.

## Deliverables (assignment: dashboards, alert rules, lab scripts, procedure guide)
* **Dashboards** – built-in Overview/Events/Alerts/Agents/Rules pages (screenshots in the report) and
  at least one team-added panel; optional OpenSearch Dashboards export (`dashboards/README.md`).
* **Alert rules** – frozen `rules/` v1.0 + Week 3 validation matrix.
* **Lab scripts** – `scripts/` (install server/agents, enable Sysmon/audit policy, certs, dev launcher)
  tested on fresh VMs from the snapshot.
* **Procedure guide** – `playbooks/` + `docs/OPERATIONS.md` + `GUIDE.md`.
* Final report + slides (`docs/PRESENTATION.md`) + live demo script.

## Day-by-day

| Day | Task | Done when |
|-----|------|-----------|
| Mon | Dashboard review with a "SOC question" list (below); add one panel (e.g. *events by asset criticality*, *MITRE tactics of open alerts*, *authentication success vs failure over time*) – store aggregation + `/api/dashboard/overview` + `app.js` | panel visible, screenshot |
| Mon | Branding check: logo, Azerbaijani accents, title `Kharibulbul SIEM` everywhere | – |
| Tue | Playbooks: walk each of the 9 playbooks with a fresh alert; fix wrong queries; add lab-specific commands | every playbook has been executed once |
| Tue | Ops guide: complete `docs/OPERATIONS.md` with your incident log and tuning log | – |
| Wed | Fresh-install test: revert a VM to "clean baseline", run the scripts from `docs/LAB-SETUP.md` blind (someone who did not write them) | agent online within 15 min |
| Wed | Hardening: API token, shared secret, TLS/mTLS (`gen-certs.sh`), UFW rules; note in the report | – |
| Thu | Report: architecture, schema, parsers, enrichment, rule engine, validation, dashboards, ops, comparison with Wazuh (what we learned from it, what we did differently, limits) | draft complete |
| Thu | Demo rehearsal (15 min): start → agents → simulate → alert → playbook → dashboard; time it | < 12 min |
| Fri | Final `cloud.md` entry, tag `v1.0`, export evidence (`data/alerts.jsonl`, screenshots) | – |

## SOC questions the dashboards must answer
1. Is everything reporting? (Agents online/silent, events per host)
2. What is happening right now? (events over time, top actions, top datasets)
3. Who is attacking what? (top source IPs / zones / countries, authentication failures)
4. What needs attention? (open alerts by severity, recent alerts, alerts by rule)
5. Is the SIEM healthy? (store size, ingest rate, parser errors, rule errors)

## Demo script (15 minutes)
1. Overview page: fleet online, baseline traffic (2 min)
2. Show one raw Windows XML event → parsed document → enrichment fields (Events drawer) (2 min)
3. `kharibulbul simulate windows-brute-force` → alert appears → open playbook → acknowledge → close (4 min)
4. `simulate port-scan` and `lolbin` → Overview alerts by severity / MITRE tags (2 min)
5. Rules page: disable a rule, reload, show `rules test` on a sample (2 min)
6. Architecture slide: what is ours vs. reference, numbers (LOC, rules, tests) (3 min)

## Questions the professor may ask – prepare answers
* Why SQLite+FTS5 instead of OpenSearch? (single process, zero external services, enough for lab
  volume, we still export to OpenSearch – show it)
* How do thresholds work with out-of-order events? (event time, sliding deque per group, GC)
* What happens when the server is down? (agent spool + replay with acks)
* How do you avoid alert storms? (suppress per rule+entity, dedupe by open alert, notify min severity)
* Why is Sysmon EID 3 not enough for port scans? (only connections that reach a listener; firewall
  drops cover closed ports – KB-NET-003)
* How would this scale? (multiple servers per zone, OpenSearch backend, agent load balancing – see
  limits section of the report)
