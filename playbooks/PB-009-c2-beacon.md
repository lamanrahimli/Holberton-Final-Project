# PB-009 · Command-and-control, beaconing, suspicious DNS, threat-intel hits

## 1. Trigger
| Rule | Meaning |
|------|---------|
| KB-TI-001 / 002 | connection or DNS query to an indicator from `intel/` |
| KB-NET-010 | DNS query for a suspicious TLD |
| KB-NET-011 | DNS query from a process in a user-writable directory |
| KB-NET-012 | DNS query burst (tunnelling / DGA) |
| KB-NET-013 | paste / tunnelling / anonymisation services |
| KB-NET-020 / 021 | outbound connection to uncommon or well-known C2 ports |
| KB-COR-005 | download utility followed by outbound connection from a user-writable binary |

## 2. Severity & SLA
high/critical → acknowledge within 10 min. A confirmed beacon means the host is under remote control: isolate before deep analysis.

## 3. Triage
```kql
host.name:<host> AND (event.code:3 OR event.action:dns-query) AND process.name:<proc>   -> the process' full network trail
destination.ip:<ip> OR dns.question.name:<name>                                          -> which other hosts talk to it (fleet scope)
host.name:<host> AND process.name:<proc> AND event.action:process-created                -> how the process started (parent, command line, user)
host.name:<host> AND event.action:file-created AND file.name:<proc>                      -> when/where the binary was written
tags:threat-intel-match                                                                  -> all intel hits in the range
```
Questions:
1. Is the destination known-bad (intel description) or only "odd" (TLD, port, process path)?
2. Periodicity: does the same process connect every N seconds/minutes (sort ascending, look at `@timestamp` gaps)? Regular intervals = beacon.
3. Which process, and is its location / parent / signature plausible for a system component?
4. Fleet: how many hosts resolve the same name or reach the same IP?

## 4. Containment
* Isolate the host; block the destination IP/domain at the firewall and DNS (sinkhole).
* Add the indicators to `intel/ips.txt` / `intel/domains.txt` with a description so KB-TI-00x tags every future hit.
* Kill the process only after noting its PID, path, hash and parent (they are needed for PB-007 / PB-008 follow-up).

## 5. Eradication & recovery
* Follow PB-007 (malware) for the binary and PB-008 for whatever restarts it.
* Reimage if the process had elevated privileges or ran for more than a few minutes.
* Egress filtering for the lab: workstations only reach the proxy / DNS server; alert on anything else (KB-NET-020 already covers uncommon ports).

## 6. Evidence
Alert JSON, network trail export, list of affected hosts, the intel entry added, packet capture if the lab has one on the segment.

## 7. False positives & tuning
* Legitimate software with a `.xyz` / `.top` domain: add the domain to a `filter_known` selection in KB-NET-010 (never remove the TLD itself).
* Developer tools (ngrok for demos, paste sites for snippets) in the lab: filter by `user.name` / host role for KB-NET-013 during the exercise window and re-enable afterwards.
* DNS burst from a browser or the DNS server itself: extend `filter_browsers` in KB-NET-012.

## 8. Close-out
Notes: indicator, process, periodicity, hosts affected, blocks applied, intel updated.
