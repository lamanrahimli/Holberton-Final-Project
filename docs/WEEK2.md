# Week 2 · Parsing, ECS-style normalisation, GeoIP enrichment

**Goal:** every log line the lab produces becomes a clean, consistent Kharibulbul Event Schema
document with location/zone and asset context. The team owns the parsers and can add one.

## Deliverables
* Parser coverage report: for each dataset, % of events handled by a specific parser
  (`kharibulbul.pipeline.parser`) vs. `generic`, and the list of unparsed formats found.
* At least **one new parser or program sub-parser** written by the team (candidates: `dhcpd`,
  Windows DNS server log, `fail2ban`, Apache error log, `pfSense`/router syslog, `auditd`).
* GeoIP working: `geoip/custom_ranges.csv` describes the lab zones; optional MaxMind DB installed;
  Overview "Source countries" panel populated.
* `docs/SCHEMA.md` reviewed; a field-mapping table per source in the report.
* Unit tests extended in `tests/test_parsers.py` for the new parser.

## Day-by-day

| Day | Task | Done when |
|-----|------|-----------|
| Mon | Export 1 h of raw events per dataset (`kharibulbul query "event.dataset:X" --json`), review `event.original` vs. parsed fields | mapping table drafted for windows.security, windows.sysmon, linux.auth, linux.firewall, nginx.access |
| Mon | Measure parser coverage: `kharibulbul query "kharibulbul.pipeline.parser:generic" --since now-24h` | list of unrecognised line formats |
| Tue | Write the new parser (see *How to add a parser*), tests, register it | `pytest` green, coverage of that dataset > 95 % |
| Wed | Normalisation review: check `process.name` lower-case, `user.name`/`user.domain` split, `network.direction`, `related.ip` on real data; fix edge cases found | no wrong values in a 500-event sample |
| Wed | GeoIP: fill `custom_ranges.csv` with the lab zones; (optional) download GeoLite2-City.mmdb on the host, copy in, `pip install maxminddb`, restart | `source.geo.name` present on every event with `source.ip` |
| Thu | Asset inventory: complete `config/assets.yml` (roles, owners, criticality); verify severity boost on a critical asset | `kharibulbul.asset.criticality` on events from dc01 |
| Thu | Threat intel: import a small IOC list into `intel/` (from a feed downloaded on the host); test with `simulate intel-hit` | KB-TI-001/002 alerts |
| Fri | Optional: enable the OpenSearch mirror (`store.opensearch.enabled: true`) on a separate VM and build one OpenSearch Dashboards visualisation from the same documents – shows the schema is ECS-compatible | index `kharibulbul-events-*` receives docs |
| Fri | Write Week 2 in `cloud.md`; update the report | – |

## How to add a parser (worked example: `fail2ban`)

1. Sample line: `Sep 27 10:00:00 srv-web01 fail2ban.actions[900]: NOTICE [sshd] Ban 10.10.99.10`
2. It is syslog → only a *program sub-parser* is needed in `kharibulbul/pipeline/parsers/syslog.py`:
   ```python
   _F2B = re.compile(r"\[(?P<jail>[^\]]+)\] (?P<action>Ban|Unban|Found) (?P<ip>\S+)")
   def parse_fail2ban(doc, msg):
       m = _F2B.search(msg)
       if not m: return False
       doc.update({"event.dataset": "linux.fail2ban", "event.module": "linux", "event.category": "intrusion_detection",
                   "event.type": "denied" if m.group("action") == "Ban" else "info",
                   "event.action": "fail2ban-" + m.group("action").lower(), "event.outcome": "success"})
       set_ip(doc, "source.ip", m.group("ip")); doc["rule.name"] = m.group("jail")
       doc["message"] = f"fail2ban {m.group('action')} {m.group('ip')} ({m.group('jail')})"
       return True
   PROGRAM_PARSERS["fail2ban.actions"] = parse_fail2ban
   ```
3. Test: `kharibulbul parse samples/fail2ban.log --fields event.action,source.ip,rule.name` and a pytest case.
4. Write a rule that uses it (e.g. "fail2ban banned an internal IP" → medium).

For a **new format** (not syslog): create `parsers/<name>.py` with `@register("<name>")`,
return `None` when the line does not match, use `base_doc()`/`set_ts()` helpers, import it in
`parsers/__init__.py`, and add its dataset to `Pipeline.select_parsers()`.

## Verification checklist
- [ ] `tags:parser-error` empty over 24 h
- [ ] `_exists_:source.geo.name` ≈ number of events with `source.ip`
- [ ] Every Windows logon event has `winlog.logon.type` as a word, not a number
- [ ] Every process event has `process.name` lower-case and `process.args`
- [ ] `docs/SCHEMA.md` matches reality (spot-check 10 fields in the Events drawer)

## Report material
Mapping tables (source field → KES field), before/after example (raw XML → document), parser
coverage numbers, GeoIP design (why a CSV first, MaxMind second), asset/intel enrichment design.
