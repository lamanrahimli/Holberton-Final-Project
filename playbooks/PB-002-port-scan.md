# PB-002 · Port scans, host sweeps and web scanning

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-NET-001 | one source touched ≥20 ports on a Windows host (Sysmon 3 inbound) |
| KB-NET-002 / 003 | UFW / Windows Firewall dropped ≥15 distinct ports from one source |
| KB-NET-004 | one source reached ≥10 hosts on the same admin port (SMB/RDP/SSH sweep) |
| KB-WEB-001 | ≥15 HTTP 404/403 for one client (directory brute force) |
| KB-WEB-003 | scanner user agent (Nikto, sqlmap, nuclei…) |
| KB-WEB-004 / 005 | sensitive path requests / injection payloads in the URL |
| KB-COR-004 | scan followed by a successful logon from the scanning IP – **critical** |

## 2. Severity & SLA
* medium/high → acknowledge within 30 min. A scan alone is reconnaissance; the urgency comes from *what follows*.
* KB-COR-004 → critical, follow PB-001 §4 immediately.

## 3. Triage
```kql
source.ip:<ip> AND event.category:network                         -> which ports / hosts (side panel: Actions, Hosts)
source.ip:<ip> AND event.action:firewall-block                    -> blocked attempts, destination.port spread
source.ip:<ip> AND event.category:web                             -> paths probed, status codes, user agent
source.ip:<ip> AND event.category:authentication                  -> did they try to log in afterwards?
source.ip:<ip> AND event.outcome:success                          -> anything succeeded?
```
Questions:
1. Where is the source? `source.geo.name` (Lab-Attacker = our own test box during exercises).
2. Vertical (many ports / one host) or horizontal (one port / many hosts)? Horizontal SMB/RDP sweeps suggest a compromised internal host.
3. Which services answered (Sysmon 3 events = the port was open and a process accepted)? Those are the exposure.
4. Web: any 200 responses to sensitive paths (`/.env`, `/.git/config`, backups)? That means data may have leaked.

## 4. Containment
* External / unknown source: block at the perimeter or host firewall.
* Internal source: it is probably a compromised host → isolate it, then treat it as a malware case (PB-007).
* Web: block the client IP at nginx (`deny <ip>;`) or the firewall; if a sensitive file was served, rotate the secrets inside it.

## 5. Eradication & recovery
* Close unnecessary listening services (`ss -tulnp`, `Get-NetTCPConnection -State Listen`).
* Web: remove exposed files, add `location ~ /\.(git|env) { deny all; }`, patch the application.

## 6. Evidence
* Alert JSON, `kharibulbul query "source.ip:<ip>" --since now-2h --json`, list of open ports found (`destination.port` side panel).

## 7. False positives & tuning
* Vulnerability scanners you run yourself (Nessus/OpenVAS/nmap from the SOC host): add their IPs to a `filter_scanner` selection in KB-NET-00x, or lower severity.
* Monitoring systems polling many hosts on one port (KB-NET-004): filter by `source.ip`.
* Web crawlers hitting many 404s: raise `threshold.count` or filter `user_agent.original|contains: [Googlebot]` (not relevant in an isolated lab).

## 8. Close-out
* Notes: source, type of scan, exposed services, follow-up alerts (yes/no). Status *closed* or *false_positive* (own scanner).
