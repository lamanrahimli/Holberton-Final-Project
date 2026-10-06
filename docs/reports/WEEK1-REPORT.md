# Week 1 report — stack stood up, agent deployed and verified

*Executed 2026-09-27 on the development machine (Windows 11, non-elevated). Lab-VM deployment
uses the same scripts; results here come from a real agent ↔ server run on one physical host.*

## 1. What was stood up

| Component | Result |
|-----------|--------|
| Kharibulbul server (`config/server.yml`) | started in ~6 s; `/api/health` OK; UI on :8080; 95 rules loaded, 0 validation problems |
| Bülbül agent (`config/agent-local-test.yml`) | registered as `laptop-test`, status `online`, remote 127.0.0.1; 2 inputs: `winlog` (System, Application, Microsoft-Windows-PowerShell/Operational) + `file` |
| Windows Event Log collection | channels bookmarked at records 9599 / 3994 / 4007 on start (`start: now`); real PowerShell operational events 40961/40962/53504 arrived and were parsed (`event.dataset: windows.powershell`) |
| Sysmon | config `sysmon/kharibulbul-sysmon.xml` validated (schema 4.90, 17 rule groups); **not installed on the dev PC** (needs elevation) — install on the lab VMs with `scripts/enable-sysmon.ps1` |
| Security channel | unreadable without elevation on the dev PC (expected) — the lab agent runs as SYSTEM via `scripts/register-agent-task.ps1` |

## 2. Resilience test (server outage while the agent keeps collecting)

| Step | Observation |
|------|-------------|
| Agent up, 1 + 5 lines written to the tailed file | 6 events on the server (7 were counted — see bug below) |
| Server process killed | agent logged `connect … failed: [WinError 10061]`, retried with back-off, wrote **1 spool file** |
| 10 more lines written while the server was down | queued to disk, inputs never blocked (`queued=0 spooled=1`) |
| Server restarted (14 s later) | agent reconnected in < 1 s and logged `replayed 10 spooled events`; spool directory empty afterwards |
| Final count | all 16 file lines present on the server; no loss, no duplicates from the outage |

**Bug found and fixed:** the file input's rotation identity on Windows hashed the first 256 bytes of
the file, so a file smaller than 256 bytes "changed identity" as it grew and its lines were read
twice (17 instead of 16 events). It now uses the NTFS file reference number (`st_dev:st_ino`) like
on Linux (`kharibulbul/agent/inputs/file.py`).

## 3. Transport security (prepared in Week 1, verified in Week 4)

`scripts/gen-certs.sh 127.0.0.1 laptop-test` produced a lab CA, a server certificate
(SAN `IP:127.0.0.1, DNS:localhost`) and an agent client certificate; `openssl verify` OK.
The script needed `MSYS_NO_PATHCONV=1` to work under Git Bash on Windows (fixed).
The mTLS + shared-secret run is documented in `WEEK4-REPORT.md`.

## 4. Scripts checked

`bash -n`: `gen-certs.sh`, `install-agent.sh`, `install-server.sh`, `run-dev.sh` — OK.
PowerShell parser: `enable-audit-policy.ps1`, `enable-sysmon.ps1`, `install-agent.ps1`,
`register-agent-task.ps1`, `run-dev.ps1` — OK.

## 5. Checklist status (from `docs/WEEK1.md`)

- [x] server health, rules validate, UI reachable
- [x] agent registered, heartbeat, events counter, spool + replay
- [x] Windows channels collected (those readable without elevation on the dev PC)
- [x] Linux-style file input (auth.log format) collected and parsed (`ssh-login-success`)
- [ ] Sysmon 1/3/11/22 and Security 4624/4625/4688 from a *real* host — requires the lab VMs (agent as SYSTEM + Sysmon); the same parsers are exercised by the synthetic scenarios (`WEEK3-VALIDATION.md`)
- [x] Timekeeping: server and agent on the same clock; engine uses event time

## 6. Numbers for the report

* Agent → server round trip (batch of 50 / 0.5 s flush): events visible in the API within ~1 s.
* Ingest on the dev laptop during `simulate all`: 245 events processed in < 1 s (27 events/s while
  the client was the bottleneck; the pipeline itself sustains thousands/s).
