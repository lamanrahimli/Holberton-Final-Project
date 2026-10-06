#!/usr/bin/env bash
# Bülbül agent installation for Linux hosts (Ubuntu/Debian/RHEL). Run as root.
# Usage: sudo bash scripts/install-agent.sh <server-ip> [/opt/kharibulbul-agent]
set -euo pipefail

SERVER_IP="${1:?usage: install-agent.sh <server-ip> [target-dir]}"
TARGET="${2:-/opt/kharibulbul-agent}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Installing python"
if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip rsync >/dev/null
elif command -v dnf >/dev/null; then dnf install -y -q python3 python3-pip rsync; fi

echo "[*] Copying agent to ${TARGET}"
mkdir -p "${TARGET}"
rsync -a --exclude 'data' --exclude '.git' --exclude '__pycache__' --exclude 'rules' --exclude 'docs' "${REPO_DIR}/" "${TARGET}/"
mkdir -p "${TARGET}/data"
python3 -m venv "${TARGET}/.venv"
"${TARGET}/.venv/bin/pip" install --quiet --upgrade pip
"${TARGET}/.venv/bin/pip" install --quiet pyyaml
"${TARGET}/.venv/bin/pip" install --quiet -e "${TARGET}" --no-deps

echo "[*] Writing config (server ${SERVER_IP})"
sed -i "s/^  host: .*/  host: ${SERVER_IP}/" "${TARGET}/config/agent.yml"

echo "[*] Making sure the logs we need exist / are enabled"
# UFW logging so port scans show up in /var/log/ufw.log (KB-NET-002)
if command -v ufw >/dev/null; then ufw logging medium || true; fi
# journald-only systems: enable the journald input instead of auth.log
if [ ! -f /var/log/auth.log ] && [ ! -f /var/log/secure ]; then
  echo "    no auth.log found -> enabling journald input"
  python3 - "$TARGET/config/agent.yml" <<'EOF'
import sys, re
p = sys.argv[1]; s = open(p).read()
s = s.replace("  - type: journald                  # systemd journal (sshd, sudo, systemd units) - needs journalctl\n    enabled: false", "  - type: journald\n    enabled: true")
open(p, "w").write(s)
EOF
fi

echo "[*] Installing systemd unit"
sed "s#/opt/kharibulbul-agent#${TARGET}#g" "${TARGET}/scripts/kharibulbul-agent.service" > /etc/systemd/system/kharibulbul-agent.service
systemctl daemon-reload
systemctl enable --now kharibulbul-agent.service
echo "Done. Check: journalctl -u kharibulbul-agent -f   and the Agents page on the server."
