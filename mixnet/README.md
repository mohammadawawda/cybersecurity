# Mixnet — Chaum-Style Mix Network

A multi-client, three-mix anonymity network in Go. Clients route fixed-length,
onion-encrypted messages through a cascade of mix servers that batch, peel one
encryption layer, shuffle, and forward each round, so no single party can link
sender to recipient. Servers talk over gRPC secured with TLS and run in isolated
Docker containers.

**The full write-up — architecture, API, encryption, security analysis, and
benchmarks — is in [`REPORT.pdf`](REPORT.pdf)** (source: `REPORT.md`).

## Quick start

```bash
./setup.sh
```

Requires Docker + Docker Compose v2 and OpenSSL; the image build needs internet
access to download Go modules. `setup.sh` generates TLS certificates and X25519
keypairs, builds the image, launches the three mixes, runs a full
message-and-reply round with two clients, prints the exit mix's per-round output
from `output/`, and tears everything down.

## Tests and benchmarks (no Docker)

```bash
go test ./internal/...                  # onion + mixcore unit tests
go run ./bench -out bench/results.csv   # measure prep / mix / end-to-end latency
python3 scripts/plot.py                 # render figures into bench/plots/
python3 scripts/build_report.py         # rebuild REPORT.pdf from REPORT.md
```

The security core (`internal/onion`, `internal/config`, `internal/mixcore`) and
the benchmark depend only on the Go standard library. The gRPC transport's
dependencies are resolved by `go mod tidy` during the Docker build, which is why
no `go.sum` is committed.

## Layout

| Path | What it is |
|------|------------|
| `main.go` | Subcommand dispatch (`server` / `client` / `keygen` / `healthcheck`) |
| `internal/onion/` | Onion crypto: X25519 + HKDF-SHA256 + AES-256-GCM, padding, replay digest |
| `internal/mixcore/` | Network-agnostic batching, shuffle, replay detection, routing |
| `internal/mixserver/` | gRPC server wiring `mixcore` to the network and output files |
| `internal/client/` | gRPC client: prepare / send / poll / decrypt |
| `internal/transport/` | TLS credential helpers |
| `proto/` | gRPC service definition and generated stubs |
| `config/config.json` | Round size, timeout, padding, parties, key paths |
| `bench/` | In-process benchmark harness, `results.csv`, and figures |
| `scripts/` | `gen_certs.sh`, `gen_config.py`, `plot.py`, `build_report.py` |
| `Dockerfile`, `docker-compose.yml`, `setup.sh` | Containerised three-mix + two-client stack |

## Notes for grading

- **Encryption** is hybrid per layer (KEM/DEM): a fresh ephemeral X25519 key
  encapsulates a 256-bit key to each mix's public key via ECDH+HKDF, and
  AES-256-GCM seals the layer. No direct public-key encryption of the payload.
- **Replay protection**: per-layer random nonces plus a global SHA-256 digest
  cache at each mix; the round number is bound as AEAD associated data.
- **Fixed-length padding**: every 3-hop outer packet is 1366 bytes regardless of
  message size.
- **Per-layer integrity** is provided by using an AEAD on every
  layer, which defeats tagging attacks.
- The proto stubs in `proto/*.pb.go` are committed so the build needs no
  `protoc`. They were generated with `protoc-gen-go` / `protoc-gen-go-grpc`.
