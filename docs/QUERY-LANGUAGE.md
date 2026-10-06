# Kharibulbul Query Language (KQL-ish)

Used in the Events page, `GET /api/events?q=…`, `GET /api/events/histogram`, `/terms`, the
`kharibulbul query` CLI and the dashboard filter box. It compiles to SQL over the SQLite store
(`kharibulbul/store/query.py`).

## Syntax

| Form | Meaning | Example |
|------|---------|---------|
| `field:value` | equality (case-insensitive) | `event.action:logon-failed` |
| `field:"two words"` | quoted value | `message:"Logon FAILED"` |
| `field:val*` / `field:v?l` | wildcards `*` (any) and `?` (one char) | `source.ip:10.10.99.*` |
| `field:>n` `>=` `<` `<=` | numeric comparison | `destination.port:>1024`, `event.severity:>=75` |
| `field:*` | field exists | `process.command_line:*` |
| `_exists_:field` | field exists (alias) | `_exists_:threat.indicator.value` |
| `tags:value` | list fields match any element | `tags:threat-intel-match`, `related.ip:10.10.99.10` |
| `free text` | full-text search on message, command line, raw, file path, url, dns name, users, hosts | `certutil urlcache`, `"kb-test"` |
| `word*` | full-text prefix | `svc_*` |
| `AND` / implicit | both must match (`a b` = `a AND b`) | `host.name:ws01 event.code:4625` |
| `OR` | either | `event.code:4625 OR event.action:ssh-login-failed` |
| `NOT` / `!` | negate | `NOT user.name:svc_backup` |
| `( … )` | grouping | `(a OR b) AND NOT c` |

Time is **not** part of the query – use the range picker / `from` & `to` parameters
(`now-15m`, `now-24h`, `2026-09-27T10:00:00Z`).

List fields (`tags`, `related.ip`, `related.user`, `process.args`, `dns.answers.data`, `host.ip`)
are searched element-wise. Numeric fields (`destination.port`, `source.port`, `event.severity`,
`process.pid`, `http.response.status_code`, …) compare as numbers.

## Cookbook

```
# authentication failures by source (then look at the side panel "Hosts"/"Users")
event.category:authentication AND event.outcome:failure

# everything a suspicious source did
source.ip:10.10.99.10 OR related.ip:10.10.99.10

# LOLBins on any host
event.action:process-created AND process.name:(certutil.exe OR mshta.exe OR regsvr32.exe OR rundll32.exe OR bitsadmin.exe)
   -> write it as: event.action:process-created AND (process.name:certutil.exe OR process.name:mshta.exe OR process.name:regsvr32.exe)

# encoded PowerShell
process.name:powershell.exe AND process.command_line:*-enc*

# DNS to suspicious TLDs
event.action:dns-query AND tags:suspicious-tld

# intel hits
tags:threat-intel-match

# high-severity events on critical assets
event.severity:>=75 AND kharibulbul.asset.criticality:critical

# web scanning
event.category:web AND http.response.status_code:404 AND source.ip:10.10.99.*

# new accounts and privileged group changes
event.category:iam AND (event.action:user-created OR event.action:group-member-added)

# what did the agent parse with problems?
tags:parser-error
```

## How it is executed

* Hot fields (`event.dataset`, `event.category`, `event.action`, `event.code`, `event.outcome`,
  `host.name`, `user.name`, `source.ip`, `destination.ip`, `destination.port`, `process.name`,
  `agent.id`, `event.severity`) are real indexed columns → fast.
* Any other field is read with `json_extract(doc, '$."field"')`.
* Free text goes through the FTS5 virtual table (`events_fts`), tokenizer `unicode61`.
* Wildcards become `LIKE` patterns with escaping; comparisons cast to REAL.

Errors return HTTP 400 with the reason (e.g. `missing ')'`).
