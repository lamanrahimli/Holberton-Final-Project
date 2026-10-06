#!/usr/bin/env bash
# Kharibulbul SIEM - server installation for Ubuntu 22.04 / Debian 12 (run as root or with sudo)
# Usage: sudo bash scripts/install-server.sh [/opt/kharibulbul]
set -euo pipefail

TARGET="${1:-/opt/kharibulbul}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_USER="kharibulbul"

echo "[*] Installing system packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git ufw >/dev/null

echo "[*] Creating service user ${SERVICE_USER}"
id -u "${SERVICE_USER}" >/dev/null 2>&1 || useradd --system --home "${TARGET}" --shell /usr/sbin/nologin "${SERVICE_USER}"

echo "[*] Copying repository to ${TARGET}"
mkdir -p "${TARGET}"
rsync -a --delete --exclude 'data' --exclude '.git' --exclude '__pycache__' "${REPO_DIR}/" "${TARGET}/"
mkdir -p "${TARGET}/data"

echo "[*] Creating virtualenv + dependencies"
python3 -m venv "${TARGET}/.venv"
"${TARGET}/.venv/bin/pip" install --quiet --upgrade pip
"${TARGET}/.venv/bin/pip" install --quiet -r "${TARGET}/requirements.txt"
"${TARGET}/.venv/bin/pip" install --quiet -e "${TARGET}"

echo "[*] Validating rules"
"${TARGET}/.venv/bin/kharibulbul" rules validate "${TARGET}/rules"

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${TARGET}"

echo "[*] Installing systemd unit"
install -m 0644 "${TARGET}/scripts/kharibulbul-server.service" /etc/systemd/system/kharibulbul-server.service
systemctl daemon-reload
systemctl enable --now kharibulbul-server.service

echo "[*] Firewall: allow agents (5044/tcp), syslog (5514/udp) and the UI (8080/tcp) from the lab only"
ufw allow from 10.10.0.0/16 to any port 5044 proto tcp comment 'kharibulbul agents' || true
ufw allow from 10.10.0.0/16 to any port 5514 proto udp comment 'kharibulbul syslog' || true
ufw allow from 10.10.0.0/16 to any port 8080 proto tcp comment 'kharibulbul ui' || true

echo
echo "Done. Status:  systemctl status kharibulbul-server"
echo "UI:            http://$(hostname -I | awk '{print $1}'):8080/"
echo "Logs:          journalctl -u kharibulbul-server -f"
echo "Config:        ${TARGET}/config/server.yml   (set api.token and ingest.shared_secret!)"
