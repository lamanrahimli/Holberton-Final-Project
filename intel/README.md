# Local threat intelligence lists

Kharibulbul enriches every event against these plain-text lists (no external
service, works offline). Files are re-read automatically when they change.

| File | Indicator type | Matched against |
|------|----------------|-----------------|
| `ips.txt` | IPv4/IPv6 address or CIDR | `source.ip`, `destination.ip` |
| `domains.txt` | domain (sub-domains match too) | `dns.question.name`, `destination.domain`, `url.domain` |
| `hashes.txt` | md5 / sha1 / sha256 | `process.hash.*`, `file.hash.sha256` |

Format: one indicator per line, optional `,description`; `#` starts a comment.

A match sets `threat.indicator.matched: true`, `threat.indicator.type/value/description`,
adds the tag `threat-intel-match`, raises `event.severity` to at least *high* and
triggers rules `KB-TI-001..003`.

## Feeding real indicators (Week 3 task)

Free feeds you can export to these files inside the lab (download on a machine with
internet, copy into the lab):

* abuse.ch Feodo Tracker / URLhaus / ThreatFox (CSV exports)
* Spamhaus DROP list (CIDRs)
* Your own IOC list from investigated alerts (`kharibulbul alerts --json`)

Keep the lab test indicators (RFC 5737 ranges, `*.badlab.xyz`) while you demo.
