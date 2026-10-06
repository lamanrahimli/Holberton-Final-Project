# Lab setup (isolated network)

Everything runs on one hypervisor (VirtualBox / VMware / Hyper-V / Proxmox) on an **internal /
host-only network** with no route to the internet. Downloads (Python, Sysmon, pip packages) are done
once on the host and copied in.

## Machines

| VM | OS | IP | Role | Runs |
|----|----|----|------|------|
| `kharibulbul` | Ubuntu 22.04 (2 vCPU, 4 GB, 40 GB) | 10.10.10.5 | SIEM server | Kharibulbul server, UI on :8080 |
| `dc01` | Windows Server 2022 (eval) | 10.10.30.10 | domain controller `lab.local` | Bülbül agent, Sysmon |
| `ws01` | Windows 11 (eval) | 10.10.20.10 | domain workstation | Bülbül agent, Sysmon |
| `srv-web01` | Ubuntu 22.04 + nginx | 10.10.30.20 | web server | Bülbül agent (files), UFW logging |
| `kali-lab` | Kali Linux | 10.10.99.10 | *test-generator* host used only for benign simulation traffic (`kharibulbul simulate`) | – |

Minimum for the project: `kharibulbul` + `ws01` + `srv-web01` (3 VMs). The DC is optional but makes
KB-WIN-011/KB-WIN-006 realistic.

Zones (see `config/assets.yml`): 10.10.10.0/24 SOC, 10.10.20.0/24 workstations,
10.10.30.0/24 servers, 10.10.99.0/24 test generator.

## Server

```bash
git clone <repo> /tmp/kharibulbul && cd /tmp/kharibulbul
sudo bash scripts/install-server.sh              # /opt/kharibulbul, venv, systemd, ufw
sudo nano /opt/kharibulbul/config/server.yml     # api.token, ingest.shared_secret, lab_networks
sudo systemctl restart kharibulbul-server
```
Open `http://10.10.10.5:8080/`, sidebar → *API token*.

Dev/demo on a laptop (Windows): `.\scripts\run-dev.ps1` (creates `.venv`, validates rules, starts).

## Windows hosts

Elevated PowerShell:
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\enable-audit-policy.ps1          # 4688 cmdline, PowerShell logging, firewall log, log sizes
.\scripts\enable-sysmon.ps1                # downloads Sysmon (or uses scripts\Sysmon.zip offline)
.\scripts\install-agent.ps1 -ServerIp 10.10.10.5 -SharedSecret '<secret>'
Get-ScheduledTask "Kharibulbul Agent" | Get-ScheduledTaskInfo
```
Verify: Agents page shows the host `online`; `kharibulbul query "host.name:ws01" --since now-10m`.

## Linux hosts

```bash
sudo bash scripts/install-agent.sh 10.10.10.5
sudo ufw logging medium && sudo ufw enable           # firewall log for KB-NET-002
sudo journalctl -u kharibulbul-agent -f
```
Appliances / hosts where you cannot install Python: `scripts/rsyslog-forward.conf`.

## TLS (optional, Week 4 hardening)

```bash
bash scripts/gen-certs.sh 10.10.10.5 ws01 srv-web01     # CA + server cert + client certs
# server.yml: ingest.tcp.tls.enabled: true, cert/key, ca: certs/ca.crt (mTLS)
# agent.yml:  server.tls.enabled: true, ca: certs/ca.crt, cert/key: certs/agent-<name>.crt/.key
```

## Generating test data safely

The lab never runs real attack tools against the SIEM hosts. Detection tests are done with
**synthetic log records** produced by `kharibulbul simulate` (from any machine that can reach
:8080) and with the hand-written samples in `samples/`. This proves that parsing, enrichment,
rules, alerts and dashboards work end-to-end while keeping the VMs clean.

```bash
kharibulbul simulate --list
kharibulbul simulate baseline                          # benign background traffic
kharibulbul simulate windows-brute-force port-scan     # specific scenarios
kharibulbul simulate all --server http://10.10.10.5:8080 --token <token>
kharibulbul replay samples/auth.log --dataset linux.auth --host srv-web01
```

## Snapshots

Take a hypervisor snapshot of every VM after Week 1 ("clean baseline") and after Week 3
("rules tuned"). Revert to the baseline before the final demo rehearsal.
