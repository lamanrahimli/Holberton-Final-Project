# Week 1 · Stand up the stack, deploy agents, enable Sysmon

**Goal:** by Friday every lab host streams logs into Kharibulbul and the team can explain how
each component works (not just that it works).

## Deliverables
* Running server (`http://10.10.10.5:8080/`), Agents page shows ≥3 hosts `online`.
* Sysmon installed with `sysmon/kharibulbul-sysmon.xml` on every Windows host; audit policy applied.
* `docs/LAB-SETUP.md` filled with *your* IPs/hostnames; `config/assets.yml` matches the lab.
* First 2 pages of the final report: architecture diagram + component table (from `docs/ARCHITECTURE.md`).
* Snapshot "clean baseline" of every VM.

## Day-by-day

| Day | Task | Owner | Done when |
|-----|------|-------|-----------|
| Mon | Build VMs, internal network, static IPs, NTP (host clock) | Infra | all hosts ping each other, `timedatectl`/`w32tm` in sync |
| Mon | Install server (`scripts/install-server.sh`), set `api.token`, `shared_secret` | SIEM lead | `/api/health` ok, UI opens, `kharibulbul rules validate` = 0 problems |
| Tue | Windows: `enable-audit-policy.ps1`, `enable-sysmon.ps1`, `install-agent.ps1` on ws01 | Endpoint | Sysmon 1/3/22 events visible: `kharibulbul query "event.dataset:windows.sysmon"` |
| Tue | Linux: `install-agent.sh` on srv-web01, UFW logging, nginx access log | Endpoint | `event.dataset:linux.auth` and `nginx.access` events arrive |
| Wed | DC (optional): agent + Sysmon; verify 4624/4625/4768 from the DC | Endpoint | `host.name:dc01 AND event.category:authentication` |
| Wed | Agent resilience test: stop the server 5 min, generate logs, start it – spool replays | SIEM lead | `Agents` events counter catches up, no gaps in `@timestamp` |
| Thu | Read the code path of one event together (`docs/ARCHITECTURE.md` § data flow); each member presents one module for 5 min | All | everybody can answer "where is X implemented?" |
| Thu | Add the lab's hosts to `config/assets.yml`; verify `host.role` on events | Detection | Overview → Top hosts shows roles in event details |
| Fri | Baseline traffic: `kharibulbul simulate baseline` + 30 min of normal use; note event rates | All | `/api/stats` → events_per_second recorded in the report |
| Fri | Snapshot VMs, write Week 1 section of `cloud.md` | Docs | – |

## Verification checklist
- [ ] `kharibulbul stats` shows `ingest.connections ≥ 3`, `pipeline.dropped_unparsed = 0`
- [ ] Windows: 4624, 4625, 4688 (with command line), Sysmon 1, 3, 11, 22, PowerShell 4104 all seen
- [ ] Linux: sshd accepted/failed, sudo, UFW BLOCK, nginx lines all parsed (`kharibulbul.pipeline.parser` ≠ `generic`)
- [ ] Agent restarts survive (scheduled task / systemd), bookmarks persist in `data/agent-state/`
- [ ] Time range on the Overview page shows the last hour of events for every host

## Things that usually go wrong
* Agent runs without admin → no Security events. Use the scheduled task (SYSTEM).
* `lab_networks` not matching your subnets → every internal logon looks "inbound" (KB-WIN-004 noise).
* Hyper-V default switch gives DHCP addresses – pin static IPs or update `assets.yml`.
* Ubuntu minimal images without rsyslog: no `/var/log/auth.log` – enable the journald input.

## Reading list (reference designs)
Wazuh architecture & agent protocol docs, Sysmon documentation (Sysinternals), ECS field reference,
SwiftOnSecurity sysmon-config (compare with ours and note what we trimmed and why).
