#!/usr/bin/env python3
"""Generate a mixnet config.json scaled to a chosen number of clients.

The committed config/config.json runs the 2-client demo. For experiments that
vary the batch size (every active client sends one message per round, so
messages_per_round is set equal to the client count), this emits a config with
N clients and M mix servers. Keys referenced here are produced afterwards by
`mixnet keygen --config <file>`.

Usage:
    python3 scripts/gen_config.py --clients 5 --servers 3 --out config/config.json
"""
import argparse
import json


def build(num_clients, num_servers, timeout_ms, padded):
    servers = [
        {
            "id": f"server{i}",
            "address": f"server{i}:{9000 + i}",
            "public_key_file": f"keys/server{i}.pub",
        }
        for i in range(1, num_servers + 1)
    ]
    clients = [
        {
            "id": f"client{i}",
            "address": f"client{i}:{9100 + i}",
            "public_key_file": f"keys/client{i}.pub",
        }
        for i in range(1, num_clients + 1)
    ]
    return {
        # Each active client sends exactly one message per round, so a full
        # batch equals the number of clients.
        "messages_per_round": num_clients,
        "round_timeout_ms": timeout_ms,
        "padded_payload_size": padded,
        "final_mix": f"server{num_servers}",
        "mix_servers": servers,
        "clients": clients,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=2)
    ap.add_argument("--servers", type=int, default=3)
    ap.add_argument("--timeout-ms", type=int, default=5000)
    ap.add_argument("--padded", type=int, default=1024)
    ap.add_argument("--out", default="-", help="output path or - for stdout")
    args = ap.parse_args()

    cfg = build(args.clients, args.servers, args.timeout_ms, args.padded)
    text = json.dumps(cfg, indent=2)
    if args.out == "-":
        print(text)
    else:
        with open(args.out, "w") as f:
            f.write(text + "\n")
        print(f"wrote {args.out}: {args.clients} clients, {args.servers} servers")


if __name__ == "__main__":
    main()
