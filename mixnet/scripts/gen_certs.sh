#!/usr/bin/env bash
#
# gen_certs.sh — generate a self-signed CA and one TLS server certificate per
# mix into ./tls/. Each certificate's SubjectAltNames include the mix's service
# name (e.g. server1), localhost and 127.0.0.1, so the same cert verifies both
# inside the Docker network (dialing serverN) and from the host (dialing
# 127.0.0.1 with ServerName=serverN). Clients are pure gRPC clients and need no
# certificate; they authenticate servers against ca.crt.
#
# Output (./tls/):
#   ca.crt, ca.key            — the private certificate authority
#   serverN.crt, serverN.key  — per-mix server certificates (N = 1,2,3)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLS_DIR="${1:-$HERE/tls}"
SERVERS=("server1" "server2" "server3")
DAYS=825

mkdir -p "$TLS_DIR"
cd "$TLS_DIR"

echo "[certs] generating CA"
openssl genrsa -out ca.key 4096 >/dev/null 2>&1
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/O=mixnet/CN=mixnet-ca" -out ca.crt >/dev/null 2>&1

for svc in "${SERVERS[@]}"; do
  echo "[certs] generating cert for $svc"
  openssl genrsa -out "${svc}.key" 2048 >/dev/null 2>&1

  # CSR with a SAN-bearing extension request.
  openssl req -new -key "${svc}.key" -subj "/O=mixnet/CN=${svc}" \
    -out "${svc}.csr" >/dev/null 2>&1

  cat > "${svc}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${svc},DNS:localhost,IP:127.0.0.1
EOF

  openssl x509 -req -in "${svc}.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days "$DAYS" -sha256 \
    -extfile "${svc}.ext" -out "${svc}.crt" >/dev/null 2>&1

  rm -f "${svc}.csr" "${svc}.ext"
done

# CA private key and serial are not needed at runtime.
chmod 600 ./*.key
rm -f ca.srl

echo "[certs] wrote CA and ${#SERVERS[@]} server certs to $TLS_DIR"
ls -1 "$TLS_DIR"
