# Writing detection rules

Rules live in `rules/**/*.yml` (several rules per file separated by `---`). They are
Sigma-inspired but evaluated by our own engine (`kharibulbul/detect/`). Validate with
`kharibulbul rules validate`, test offline with `kharibulbul rules test`, dry-run against a
running server with `POST /api/rules/test`, reload without restart via `POST /api/rules/reload`
or the *Rules → reload* button.

**Your own rules** can be written in the dashboard: *Rules → ＋ New rule* opens an editor with a
commented template and the next free id (`KB-CUS-001` …); *Validate & test* runs the rule against log
lines you paste; *Save rule* stores it as `custom/rules/<id>.yml` (one rule per file) and reloads the
engine. Custom rules can be edited and deleted there; shipped rules are read-only but can be *cloned
as a custom rule*. A rule is rejected when a required field is missing, the condition does not parse,
a modifier is unknown, a regex does not compile, a CIDR is invalid, the playbook does not exist, or the
id is already used. API: `GET /api/rules/template`, `POST /api/rules`, `PUT|DELETE /api/rules/{id}`.

## Anatomy

```yaml
id: KB-WIN-001                      # unique, stable, used in alerts and stats
title: Windows brute force - many failed logons from one source
description: >                      # shown to the analyst
  10+ failed logons from one IP against one host in 5 minutes.
severity: high                      # informational | low | medium | high | critical
enabled: true
tags: [windows, authentication, brute-force]
mitre:
  - { technique: T1110.001, tactic: credential-access }
logsource: { dataset: windows.security }   # cheap pre-filter: dataset | module | category
detection:
  selection:                        # all fields in a selection must match (AND)
    event.code: "4625"
  filter_machine:
    user.name|endswith: "$"
  condition: selection and not filter_machine
threshold:                          # optional aggregation
  count: 10
  window: 5m
  group_by: [host.name, source.ip]
  # distinct: user.name            # count distinct values instead of events
suppress: 10m                       # no second alert for the same entity within 10 min
playbook: playbooks/PB-001-brute-force.md
falsepositives: [...]
references: [...]
```

### Rule kinds

| Kind | How | Alert when |
|------|-----|------------|
| **match** | `detection` only | the first matching event (per `group_by` entity if given, see below) |
| **threshold** | `detection` + `threshold` | `count` matching events (or `distinct` values of a field) for the same `group_by` key inside a sliding `window` |
| **sequence** | `sequence` | ordered stages complete for the same `by` key within `within` |

Shorthand: a match rule with a top-level `group_by: [host.name]` becomes "alert once per host"
(internally `threshold: {count: 1, window: 1m, group_by: [...]}`), which gives nicer entities and
per-entity suppression.

### Selections

* A selection is a mapping `field|modifiers: value`; a **list of values means OR**.
* A selection can also be a **list of mappings** (OR between mappings) or a **bare string**
  (contained in `message`/`event.original`/`process.command_line`).
* Matching is **case-insensitive** unless `|cs` is used; `*` and `?` are wildcards in plain values.
* Lists in the document (`tags`, `process.args`, `related.ip`) match if any element matches.

| Modifier | Meaning | Example |
|----------|---------|---------|
| `contains` | substring | `process.command_line\|contains: urlcache` |
| `startswith` / `endswith` | prefix / suffix | `process.executable\|startswith: "c:\\windows\\"` |
| `re` | regular expression (search) | `process.command_line\|re: '-enc\s+[A-Za-z0-9+/=]{20,}'` |
| `all` | every listed value must match | `cmd\|contains\|all: [process, call, create]` |
| `cidr` | IP in network | `source.ip\|cidr: 10.10.99.0/24` |
| `gt` `gte` `lt` `lte` | numeric | `destination.port\|gte: 1024` |
| `exists` | presence | `process.hash.sha256\|exists: true` |
| `not` | negate the whole field check | `user.name\|endswith\|not: "$"` |
| `cs` | case-sensitive | `process.name\|cs: Sysmon64.exe` |

`field: null` matches when the field is absent. Numbers compare numerically when both sides are numeric.

### Conditions

`condition:` uses selection names with `and`, `or`, `not`, parentheses, `1 of sel_*`,
`all of sel_*`, `1 of them`, `all of them`. Without a condition all selections are AND-ed.

### Thresholds

* `group_by` – entity fields; events with different values are counted separately.
* `window` – sliding window over **event time** (`5m`, `90s`, `1h`).
* `distinct` – count unique values of this field instead of events (port scans, password spraying).
* After firing, the group's counter resets and `suppress` prevents an immediate re-alert; more
  matching events update the open alert's count instead.

### Sequences

```yaml
sequence:
  by: [source.ip]
  within: 15m
  stages:
    - name: failures
      selection: { event.code: "4625" }
      count: 5                       # this many events needed before moving on
    - name: success
      selection: { event.code: "4624" }
```
Stages must happen in order for the same `by` key; a completed track is consumed.

### Suppression & entities

`suppress` (default `detect.default_suppress`, 10 m) is per rule + `group_key`. The alert manager
also de-duplicates: if an open alert for the same rule+entity exists inside the suppress window,
it increments `count`, updates `last_seen`, appends sample events and sends an *update* notification.

## Severity

Alert `severity_score` = rule severity (10/30/50/75/95) + asset criticality boost
(medium +5, high +15, critical +25) and is forced to at least *high* when the event has a
threat-intel match. The name is derived from the score.

## Workflow for a new rule (Week 3)

1. Reproduce the behaviour with **synthetic events** (`kharibulbul simulate --out x.jsonl`, or write
   log lines by hand in `samples/`), never with real attack tooling in the lab network.
2. Inspect the parsed fields: `kharibulbul parse x.jsonl --fields event.action,process.name,process.command_line`.
3. Write the rule; run `kharibulbul rules validate rules`.
4. Offline test: `kharibulbul rules test rules/sysmon/lolbin.yml x.jsonl -v` – expect matches and alerts.
5. Baseline test: `kharibulbul rules test <rule> samples/baseline.jsonl` must produce **no** alerts
   (generate it with `kharibulbul simulate baseline --out samples/baseline.jsonl`); also run it against a
   day of real lab traffic exported from the Events page.
6. Add a unit test in `tests/test_pipeline_e2e.py` (`EXPECTED`) if you add a scenario.
7. Reload on the server and watch the *Rules* page hit counter for a day; tune filters; document
   false positives in the rule and the playbook.

## Naming

`KB-<AREA>-<NNN>`: `WIN` Windows Security/System, `SYS` Sysmon/process, `PS` PowerShell,
`NET` network/DNS/firewall, `LNX` Linux, `WEB` web servers, `TI` threat intel, `COR` correlation,
`KB` SIEM health. Keep ids stable – alerts, stats and reports reference them.
