""""Add agent" wizard: builds the agent configuration and the install guide for a new host.

The server issues the agent id, stores the agent as ``pending`` and hands back a ready-to-save YAML
file plus the steps to run on the host.  Nothing is pushed to the host: the operator copies the
file there and starts the agent, which then shows up as ``online`` under the same id.
"""
from __future__ import annotations

import json
import re

PROFILES = {
    "windows": "Windows - standard user (System, Application, PowerShell, Defender, RDP sessions, Firewall)",
    "windows-admin": "Windows - Administrator (adds Security, Sysmon, Task Scheduler and the firewall log file)",
    "linux-files": "Linux - log files (/var/log/auth.log, syslog, ufw, nginx)",
    "linux-journald": "Linux - systemd journal (journald-only distributions, WSL)",
}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$")

_WIN_USER = """  - type: winlog
    channels:
      - System
      - Application
      - Microsoft-Windows-PowerShell/Operational
      - Microsoft-Windows-Windows Defender/Operational
      - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
      - Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
      - Microsoft-Windows-Bits-Client/Operational
    interval: 2
    batch: 300
    start: now                     # only new events; 'beginning' backfills the whole channel
    exclude_event_ids:
      System: [16, 1014, 7000, 7001]
"""
_WIN_ADMIN = """  - type: winlog                   # the Security and Sysmon channels need an elevated (Administrator) agent
    channels:
      - Security
      - System
      - Microsoft-Windows-Sysmon/Operational
      - Microsoft-Windows-PowerShell/Operational
      - Microsoft-Windows-Windows Defender/Operational
      - Microsoft-Windows-TaskScheduler/Operational
      - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
    interval: 2
    batch: 500
    start: now
    exclude_event_ids:
      Security: [4656, 4658, 4663, 4690, 5152, 5158, 4703]   # very noisy object-access / WFP allow events
      System: [16, 1014, 7000, 7001]
  - type: file                     # Windows Firewall log (enable with scripts/enable-audit-policy.ps1)
    paths: ["C:\\\\Windows\\\\System32\\\\LogFiles\\\\Firewall\\\\pfirewall.log"]
    dataset: windows.firewall_log
    start: end
"""
_LINUX_FILES = """  - type: file
    paths: ["/var/log/auth.log", "/var/log/secure"]     # Debian/Ubuntu | RHEL
    dataset: linux.auth
    start: end
  - type: file
    paths: ["/var/log/syslog", "/var/log/messages"]
    dataset: linux.syslog
    start: end
  - type: file
    paths: ["/var/log/ufw.log", "/var/log/kern.log"]
    dataset: linux.firewall
    start: end
  - type: file
    paths: ["/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"]
    dataset: nginx.access
    start: end
"""
_LINUX_JOURNALD = """  - type: journald                 # sshd, sudo, su, useradd, cron, kernel, systemd units (needs journalctl)
    dataset: linux.journald
    units: []                      # empty = whole journal
  # do not add the /var/log file inputs as well when rsyslog writes the same lines there: every event would arrive twice
"""
_INPUTS = {"windows": _WIN_USER, "windows-admin": _WIN_ADMIN, "linux-files": _LINUX_FILES, "linux-journald": _LINUX_JOURNALD}


def _q(value: str) -> str:
    return json.dumps(str(value))


def clean_params(body: dict, defaults: dict) -> dict:
    """Validate the wizard input. Raises ValueError with a message for the operator."""
    name = str(body.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("name: 1-48 characters, letters / digits / . _ - (it becomes agent.name and the file name)")
    profile = str(body.get("profile") or "").strip()
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {', '.join(PROFILES)}")
    host = str(body.get("server_host") or defaults.get("server_host") or "").strip()
    if not host or not re.match(r"^[A-Za-z0-9.:_-]{1,253}$", host):
        raise ValueError("server_host: the address of this SIEM server as the new host can reach it (IP or DNS name)")
    try:
        port = int(body.get("port") or defaults.get("port") or 5044)
    except (TypeError, ValueError):
        raise ValueError("port must be a number") from None
    if not 1 <= port <= 65535:
        raise ValueError("port must be 1-65535")
    zone = str(body.get("zone") or "").strip()
    if zone and not re.match(r"^[A-Za-z0-9 ._-]{1,40}$", zone):
        raise ValueError("zone: letters, digits, space . _ - only")
    return {"name": name, "profile": profile, "os": "windows" if profile.startswith("windows") else "linux",
            "server_host": host, "port": port, "zone": zone, "tls": bool(body.get("tls", defaults.get("tls", False))),
            "secret_required": bool(defaults.get("secret_required"))}


def build_config(p: dict, agent_id: str) -> str:
    labels = ", ".join(f"{k}: {_q(v)}" for k, v in (("zone", p["zone"]), ("os", p["os"]), ("enrolled", "dashboard")) if v)
    tls = ('  tls: { enabled: true, ca: certs/ca.crt, verify: true }   # copy certs/ca.crt from the server (scripts/gen-certs.sh)\n'
           if p["tls"] else "  tls: { enabled: false }\n")
    return (
        f"# Bülbül agent - {p['name']} ({PROFILES[p['profile']]})\n"
        f"# Generated by the Kharibulbul dashboard (Agents -> Add agent). Save as config/agent-{p['name']}.yml on the host and run:\n"
        f"#   python -m kharibulbul agent -c config/agent-{p['name']}.yml\n"
        "agent:\n"
        f"  name: {_q(p['name'])}\n"
        f"  id: {_q(agent_id)}            # issued by the server: the agent appears under this id\n"
        f"  id_file: data/agent-{p['name']}/agent.id\n"
        f"  labels: {{ {labels} }}\n"
        "\n"
        "server:\n"
        f"  host: {_q(p['server_host'])}\n"
        f"  port: {p['port']}\n"
        f"{tls}"
        '  shared_secret: "${KB_SHARED_SECRET:-}"'
        + ("     # this server requires the secret: set KB_SHARED_SECRET before starting\n" if p["secret_required"] else "\n")
        + "  reconnect_min: 1\n"
        "  reconnect_max: 30\n"
        "\n"
        f"spool: {{ dir: data/agent-{p['name']}/spool, max_mb: 200 }}\n"
        "batch: { size: 100, flush_interval: 1.0 }\n"
        "heartbeat_interval: 30\n"
        "log_level: INFO\n"
        "\n"
        "inputs:\n"
        f"{_INPUTS[p['profile']]}"
    )


def install_steps(p: dict) -> list[dict]:
    """The guide shown next to the generated file: what to do on the new host, in order."""
    name, host, port, win = p["name"], p["server_host"], p["port"], p["os"] == "windows"
    cfg = f"config\\agent-{name}.yml" if win else f"config/agent-{name}.yml"
    steps = [{
        "title": "Copy Kharibulbul to the host",
        "text": ("Copy the repository folder (kharibulbul/, config/, scripts/, pyproject.toml, requirements.txt) to the new host, "
                 "for example to C:\\Kharibulbul. Python 3.10+ is required; the agent itself only needs PyYAML."
                 if win else
                 "Copy the repository folder to the new host, for example to /opt/kharibulbul-agent. Python 3.10+ is required; "
                 "the agent itself only needs PyYAML."),
        "commands": ["python -m pip install pyyaml", "python -m pip install --no-deps -e ."] if win else
                    ["sudo apt-get install -y python3 python3-yaml    # or: python3 -m pip install pyyaml"],
    }, {
        "title": "Save the configuration file",
        "text": f"Download the file below and save it on the host as {cfg} (inside the copied folder). "
                "It already contains this server's address and the id issued for this agent.",
        "commands": [],
    }, {
        "title": "Check that the host can reach the server",
        "text": f"The agent connects to {host}:{port} (TCP). Open that port on the server's firewall for the host's network.",
        "commands": [f"Test-NetConnection {host} -Port {port}"] if win else [f"nc -vz {host} {port}"],
    }]
    if p["secret_required"]:
        steps.append({
            "title": "Set the shared secret",
            "text": "This server only accepts agents that present its shared secret (ingest.shared_secret). "
                    "Ask the SIEM administrator for it and set it in the environment of the agent - it is not written into the file.",
            "commands": ['$env:KB_SHARED_SECRET = "<secret>"'] if win else ['export KB_SHARED_SECRET="<secret>"'],
        })
    if p["tls"]:
        steps.append({
            "title": "Copy the CA certificate",
            "text": "TLS is enabled: copy certs/ca.crt from the server to certs/ca.crt on the host so the agent can verify the server.",
            "commands": [],
        })
    if p["profile"] == "windows-admin":
        steps.append({
            "title": "Prepare the audit sources (once, elevated)",
            "text": "The Security and Sysmon channels need an elevated PowerShell. The scripts switch on the advanced audit policy, "
                    "4688 command lines, PowerShell script-block logging and install Sysmon with our configuration.",
            "commands": ["Set-ExecutionPolicy -Scope Process Bypass", ".\\scripts\\enable-audit-policy.ps1", ".\\scripts\\enable-sysmon.ps1"],
        })
    steps.append({
        "title": "Start the agent",
        "text": ("Run it from the copied folder" + (" in an elevated PowerShell (Administrator)." if p["profile"] == "windows-admin" else ".")
                 if win else "Run it from the copied folder as root (reading /var/log/auth.log and the journal needs it)."),
        "commands": [f"python -m kharibulbul agent -c {cfg}"] if win else [f"sudo python3 -m kharibulbul agent -c {cfg}"],
    })
    steps.append({
        "title": "Run it as a service (optional)",
        "text": ("Register a scheduled task that starts the agent as SYSTEM at boot." if win else
                 "Install the systemd unit: copy scripts/kharibulbul-agent.service to /etc/systemd/system/, point ExecStart at "
                 f"{cfg} and enable it."),
        "commands": [f'.\\scripts\\register-agent-task.ps1 -Target (Get-Location).Path -Config "{cfg}"'] if win else
                    ["sudo cp scripts/kharibulbul-agent.service /etc/systemd/system/",
                     "sudo systemctl daemon-reload && sudo systemctl enable --now kharibulbul-agent"],
    })
    steps.append({
        "title": "Verify",
        "text": f"Within a few seconds the agent changes from pending to online in this table. Its events: search agent.name:\"{name}\" "
                "on the Events page. If it stays pending, read the agent's console output (connection refused = firewall, "
                "rejected hello = shared secret).",
        "commands": [],
    })
    return steps
