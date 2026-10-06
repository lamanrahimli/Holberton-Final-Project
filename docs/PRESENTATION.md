# Final presentation outline (20 min + questions)

## Slides

1. **Title** – Kharibulbul (Xarıbülbül) SIEM, logo, team, "a national mini-SIEM built from scratch".
   Why the name: the Khari Bulbul orchid of Shusha/Karabakh – the lip of the flower looks like a
   nightingale sitting in it; our SIEM *listens* to every host the way a nightingale listens.
2. **The assignment and the professor's challenge** – "anyone can install Wazuh" → we built our own:
   agent, ingest protocol, parsers, schema, enrichment, store, query language, rule engine, alerting,
   dashboards, CLI. Wazuh/OpenSearch/Beats/Sysmon used as *reference designs* only.
3. **Numbers** – lines of code (`git ls-files '*.py' | xargs wc -l`), 95 rules (18 written by the team), 52 simulate
   scenarios, 98 tests, 10 parsers, N hosts, events/day, alerts/day after tuning.
4. **Architecture** – diagram from `docs/ARCHITECTURE.md`; one slide per layer follows.
5. **Collection** – Bülbül agent: inputs, batching/acks/spool, Sysmon config decisions, audit policy.
6. **Parsing & schema** – raw XML → KES document (real example), parser registry, coverage numbers.
7. **Enrichment** – lab zones/GeoIP, asset criticality → severity boost, threat-intel lists.
8. **Storage & search** – SQLite+FTS5 design, indexed hot columns, query language examples.
9. **Detection engine** – match / threshold (count & distinct) / sequence; event-time windows;
   suppression; MITRE mapping; rule example (KB-WIN-001) and a sequence (KB-COR-001).
10. **Safe validation** – synthetic log generator, samples, unit tests; validation matrix; baseline noise
    before/after tuning.
11. **Alerting & response** – alert lifecycle, notifications, playbooks (show PB-001).
12. **Dashboards** – screenshots: Overview, Events drawer, Alerts, Rules, Agents.
13. **Operations** – install scripts, systemd/scheduled task, backup, retention, hardening (TLS/mTLS, tokens).
14. **Comparison with Wazuh** – what we borrowed (agent/manager model, decoders→rules→alerts, ECS
    naming), what we simplified (single process, SQLite), what we skipped (FIM, vulnerability detection,
    SCA, agent remote commands) and why.
15. **Limits & future work** – single node, no HA, no FIM/agent commands, basic UI, GeoIP needs MaxMind
    for real internet ranges, more parsers (Windows DNS server, cloud audit logs), ML baselines.
16. **Live demo** (see `docs/WEEK4.md` demo script).
17. **Lessons learned** – per member, one sentence each.

## Report structure (suggested, ~30 pages)
1. Introduction & objectives · 2. Related work (Wazuh, ELK/OpenSearch, Sigma, ECS) · 3. Architecture ·
4. Collection (agents, Sysmon, audit policy) · 5. Parsing & schema · 6. Enrichment · 7. Storage & query ·
8. Detection engine & rule set · 9. Validation methodology & results · 10. Alerting, playbooks, operations ·
11. Dashboards · 12. Security of the SIEM itself · 13. Evaluation, limits, future work · 14. Team & process ·
Appendices: rule catalogue (from `kharibulbul rules list`), schema table, scripts, `cloud.md` log.

## Evidence to collect during the month
* Screenshots after each week (dashboards with real lab data).
* `data/alerts.jsonl` excerpts, validation matrix, tuning log.
* `pytest` output, `kharibulbul rules validate` output, `/api/stats` snapshots.
* Git history (commits per member) – shows real teamwork.
