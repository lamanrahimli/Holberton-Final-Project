#!/usr/bin/env bash
# Generate a lab CA, a server certificate and (optionally) client certificates for mutual TLS.
# Usage: bash scripts/gen-certs.sh <server-ip-or-name> [agent-name ...]
# Then in config/server.yml: ingest.tcp.tls.enabled: true, cert/key/ca = certs/...
#      in config/agent*.yml: server.tls.enabled: true, ca: certs/ca.crt (+ cert/key for mTLS)
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: keep "/C=AZ/O=..." as an OpenSSL subject, not a path
SERVER="${1:?usage: gen-certs.sh <server-ip-or-name> [agent-name ...]}"
shift || true
OUT="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$OUT"
cd "$OUT"

if [ ! -f ca.key ]; then
  echo "[*] CA"
  openssl req -x509 -newkey rsa:4096 -sha256 -days 1825 -nodes -keyout ca.key -out ca.crt \
    -subj "/C=AZ/O=Kharibulbul Lab/CN=Kharibulbul Lab CA"
fi

echo "[*] Server certificate for ${SERVER}"
SAN="IP:${SERVER}"
[[ "$SERVER" =~ ^[0-9.]+$ ]] || SAN="DNS:${SERVER}"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/C=AZ/O=Kharibulbul Lab/CN=${SERVER}"
printf "subjectAltName=%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" "$SAN" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256 -extfile server.ext
rm -f server.csr server.ext

for AGENT in "$@"; do
  echo "[*] Client certificate for agent ${AGENT}"
  openssl req -newkey rsa:2048 -nodes -keyout "agent-${AGENT}.key" -out "agent-${AGENT}.csr" -subj "/C=AZ/O=Kharibulbul Lab/CN=${AGENT}"
  printf "extendedKeyUsage=clientAuth\n" > client.ext
  openssl x509 -req -in "agent-${AGENT}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "agent-${AGENT}.crt" -days 825 -sha256 -extfile client.ext
  rm -f "agent-${AGENT}.csr" client.ext
done
chmod 600 *.key
echo "Certificates written to ${OUT}"
