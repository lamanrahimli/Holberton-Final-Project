# Team roles (3–4 members, 1 month)

Everyone touches every layer at least once (the defence is individual), but each member *owns* one
area and its chapter of the report.

| Role | Owns | Week 1 | Week 2 | Week 3 | Week 4 |
|------|------|--------|--------|--------|--------|
| **SIEM lead / backend** | server, store, API, ingest protocol, CI (`pytest`) | install server, agent protocol demo, resilience test | query language & store review, OpenSearch mirror (optional) | alert manager + notifications, engine performance numbers | hardening (TLS, tokens), fresh-install test, architecture chapter |
| **Endpoint / collection** | agents, Sysmon config, audit policy, Linux logging | deploy agents, Sysmon, audit policy on all hosts | new parser/sub-parser, parser coverage report | Windows/Linux-side test data (`samples/`), agent tuning (`exclude_event_ids`) | lab scripts chapter, LAB-SETUP walkthrough |
| **Detection engineer** | rules, MITRE mapping, simulate scenarios, tuning log | asset inventory, first look at baseline events | normalisation review, threat intel & GeoIP data | write ≥5 rules, tuning, validation matrix | rules chapter, demo scenarios |
| **SOC analyst / docs** (4th member, or shared) | playbooks, ops guide, dashboards, report, `cloud.md` | LAB-SETUP with real IPs, Week 1 log | schema doc & mapping tables | tabletop exercise, playbook fixes, webhook | dashboard panel, slides, demo script, final report |

## Weekly rhythm
* **Monday 30 min stand-up**: last week's deliverables (checklist in `docs/WEEKn.md`), blockers.
* **Wednesday pairing**: two members swap areas for 2 h (knowledge transfer for the defence).
* **Friday review**: run `pytest`, `kharibulbul rules validate`, update `cloud.md`, snapshot VMs, git tag `weekN`.

## Definition of done (per deliverable)
1. Works on a fresh VM from the snapshot, following only the docs.
2. Has a test (unit test, simulate scenario, or a documented manual check).
3. Is described in the report chapter of its owner and in `cloud.md`.
4. Reviewed by one other member.
