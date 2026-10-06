#!/usr/bin/env bash
# Kharibulbul - Bülbül agent inside WSL 2 (Ubuntu) shipping to the server on the Windows host.
#
#   wsl -d Ubuntu -u root bash scripts/wsl-agent.sh setup      # python3-yaml, systemd (journald) - once
#   wsl -d Ubuntu -u root bash scripts/wsl-agent.sh run        # start the agent (Ctrl+C stops it)
#   wsl -d Ubuntu -u root bash scripts/wsl-agent.sh activity   # benign admin actions + synthetic sshd lines -> journal
#
# From PowerShell the same three are:  .\scripts\run-dev.ps1 -WslSetup | -WslAgent | -WslActivity
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
MODE="${1:-run}"

probe() {
  python3 - "$1" "${2:-5044}" <<'PY'
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()
    print("ok")
except OSError:
    print("no")
PY
}

server_host() {
  # mirrored networking: the Windows loopback is reachable; NAT: the Windows host is the default gateway
  if [ "$(probe 127.0.0.1)" = "ok" ]; then echo 127.0.0.1; return; fi
  local gw
  gw="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"
  if [ -n "$gw" ] && [ "$(probe "$gw")" = "ok" ]; then echo "$gw"; return; fi
  local ns
  ns="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
  if [ -n "$ns" ] && [ "$(probe "$ns")" = "ok" ]; then echo "$ns"; return; fi
  echo "${gw:-127.0.0.1}"
}

case "$MODE" in
  setup)
    if ! python3 -c "import yaml" 2>/dev/null; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq && apt-get install -y -qq python3-yaml >/dev/null
    fi
    python3 -c "import yaml, sys; print('python', sys.version.split()[0], '| PyYAML', yaml.__version__)"
    if ! grep -qs 'systemd *= *true' /etc/wsl.conf; then
      printf '[boot]\nsystemd=true\n' >> /etc/wsl.conf
      echo "systemd enabled in /etc/wsl.conf - restart the distro:  wsl --terminate Ubuntu"
    fi
    # WSL shares the Windows hostname by default; give the Linux side its own name so the two
    # agents show up as two hosts in the dashboards (takes effect after  wsl --terminate Ubuntu)
    if ! grep -qs '^hostname *=' /etc/wsl.conf; then
      printf '[network]\nhostname=ubuntu-wsl\n' >> /etc/wsl.conf
      echo "hostname ubuntu-wsl set in /etc/wsl.conf - restart the distro:  wsl --terminate Ubuntu"
    fi
    echo "systemd state: $(systemctl is-system-running 2>/dev/null || echo 'not running yet')"
    ;;
  run)
    HOST="$(server_host)"
    export KB_SERVER_HOST="$HOST"
    echo "[wsl-agent] Windows host / Kharibulbul server = $HOST:5044 (KB_SERVER_HOST)"
    exec python3 -m kharibulbul agent -c config/agent-linux-wsl.yml
    ;;
  activity)
    # Benign administrative actions and synthetic log lines written to the *local* journal so the
    # agent -> server -> parser -> rule path can be watched with real Linux telemetry.
    me="$(id -un)"
    echo "[activity] admin actions (useradd / usermod / userdel, sudo) ..."
    if ! id kbdemo >/dev/null 2>&1; then useradd -m -s /bin/bash kbdemo; fi
    usermod -aG sudo kbdemo || true
    sudo -n true 2>/dev/null || true
    userdel -r kbdemo 2>/dev/null || true
    echo "[activity] synthetic sshd lines (same content as the ssh-brute-force scenario) ..."
    for u in root admin oracle test backup; do
      logger -p auth.info -t sshd "Invalid user $u from 10.10.99.10 port 51234"
      logger -p auth.info -t sshd "Failed password for invalid user $u from 10.10.99.10 port 51234 ssh2"
    done
    for i in 1 2 3 4 5 6; do
      logger -p auth.info -t sshd "Failed password for $me from 10.10.99.10 port 5123$i ssh2"
    done
    logger -p auth.info -t sshd "Accepted password for $me from 10.10.99.10 port 51240 ssh2"
    logger -p auth.notice -t sudo "kbdemo : TTY=pts/0 ; PWD=/home/kbdemo ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    echo "[activity] done - watch the Alerts page (KB-LNX-001/002, KB-COR-002, KB-LNX-017)"
    ;;
  *)
    echo "usage: $0 setup|run|activity"
    exit 2
    ;;
esac
