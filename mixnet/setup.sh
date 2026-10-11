#!/usr/bin/env bash
#
# setup.sh — one-command demo of the mix network.
#
# Generates TLS certificates and X25519 keypairs, builds the image, launches the
# three mixes, runs a full message-and-reply round with two clients, prints the
# exit mix's per-round output, and tears everything down on exit.
#
# Requirements: docker + docker compose v2, openssl. Building the image needs
# internet access (Go module download).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

IMAGE="mixnet:latest"

cleanup() {
  echo
  echo "[setup] tearing down"
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p output tls config/keys
# Start from a clean output directory so the demo's round files are unambiguous.
rm -f output/round_*.txt 2>/dev/null || true

echo "[setup] 1/5 generating TLS certificates"
bash scripts/gen_certs.sh "$HERE/tls"

echo "[setup] 2/5 building image ($IMAGE)"
docker compose build

echo "[setup] 3/5 generating X25519 keypairs into config/keys"
# config is mounted read-only at runtime; for this one-off generation step we
# mount it read-write so keygen can write the key files.
docker run --rm -v "$HERE/config:/app/config" "$IMAGE" keygen

echo "[setup] 4/5 starting the three mixes and waiting for health"
docker compose up -d --wait server1 server2 server3

echo "[setup] 5/5 running two clients (each sends to the other in round 1)"
# Run both clients concurrently so their two messages fill the round's batch;
# each then polls and receives the other's message (the reply).
docker compose run --rm client1 & p1=$!
docker compose run --rm client2 & p2=$!
set +e
wait "$p1"; r1=$?
wait "$p2"; r2=$?
set -e
echo "[setup] client1 exit=$r1  client2 exit=$r2"

echo
echo "[setup] exit mix per-round output:"
shopt -s nullglob
files=(output/round_*.txt)
if (( ${#files[@]} == 0 )); then
  echo "  (no round files written — check 'docker compose logs server3')"
else
  for f in "${files[@]}"; do
    echo "  --- $f ---"
    sed 's/^/    /' "$f"
  done
fi

echo
echo "[setup] demo complete"
