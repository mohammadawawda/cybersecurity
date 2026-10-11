"""
Path ORAM — Performance Benchmarks
====================================
Measures:
1. Throughput (requests/sec) vs. N (DB size)
2. Latency (time/request) vs. Throughput
3. Bandwidth Overhead vs. Block Size (B)
4. Maximum Stash Size over 1,000 operations vs. N
"""

import time
import os
import math
import random
import statistics
from path_oram import create_oram



def benchmark_throughput_vs_n(n_values, block_size=256, num_ops=500, num_runs=3):
    """
    Measure throughput (requests/sec) for different database sizes N.
    Each run performs num_ops mixed operations (store/retrieve).
    Results are averaged over num_runs.
    """
    print("=" * 60)
    print("Benchmark 1: Throughput (req/sec) vs. N (DB size)")
    print(f"  Block size B={block_size}, Operations per run={num_ops}, Averaged over {num_runs} runs")
    print("=" * 60)

    results = []
    for N in n_values:
        run_throughputs = []
        for run in range(num_runs):
            client, server = create_oram(N, block_size)

            # Pre-store half the blocks
            for i in range(min(N // 4, 50)):
                client.store_data(server, i, os.urandom(block_size // 2))

            start = time.perf_counter()
            for op in range(num_ops):
                block_id = random.randint(0, N - 1)
                if random.random() < 0.5:
                    client.store_data(server, block_id, os.urandom(block_size // 2))
                else:
                    client.retrieve_data(server, block_id)
            elapsed = time.perf_counter() - start

            throughput = num_ops / elapsed
            run_throughputs.append(throughput)

        avg_throughput = statistics.mean(run_throughputs)
        std_throughput = statistics.stdev(run_throughputs) if len(run_throughputs) > 1 else 0
        results.append((N, avg_throughput, std_throughput))
        print(f"  N={N:>6d}: {avg_throughput:>8.1f} req/sec (±{std_throughput:.1f})")

    return results



def benchmark_latency_vs_throughput(n_values, block_size=256, num_ops=500, num_runs=3):
    """
    Measure both latency (ms/request) and throughput for different N values.
    This produces data to plot latency vs throughput.
    """
    print("\n" + "=" * 60)
    print("Benchmark 2: Latency (ms/req) vs. Throughput (req/sec)")
    print(f"  Block size B={block_size}, Operations per run={num_ops}, Averaged over {num_runs} runs")
    print("=" * 60)

    results = []
    for N in n_values:
        run_latencies = []
        run_throughputs = []
        for run in range(num_runs):
            client, server = create_oram(N, block_size)

            # Pre-store some blocks
            for i in range(min(N // 4, 50)):
                client.store_data(server, i, os.urandom(block_size // 2))

            latencies = []
            for op in range(num_ops):
                block_id = random.randint(0, N - 1)
                t0 = time.perf_counter()
                if random.random() < 0.5:
                    client.store_data(server, block_id, os.urandom(block_size // 2))
                else:
                    client.retrieve_data(server, block_id)
                t1 = time.perf_counter()
                latencies.append((t1 - t0) * 1000)  # ms

            avg_lat = statistics.mean(latencies)
            throughput = num_ops / (sum(latencies) / 1000)
            run_latencies.append(avg_lat)
            run_throughputs.append(throughput)

        avg_latency = statistics.mean(run_latencies)
        avg_throughput = statistics.mean(run_throughputs)
        results.append((N, avg_latency, avg_throughput))
        print(f"  N={N:>6d}: latency={avg_latency:>8.3f} ms/req, throughput={avg_throughput:>8.1f} req/sec")

    return results



def benchmark_bandwidth_vs_blocksize(block_sizes, N=128, num_ops=200, num_runs=3):
    """
    Measure bandwidth overhead for different block sizes.
    Bandwidth overhead = total bytes transferred / actual payload bytes.
    
    Each access reads and writes one full path of (L+1) buckets, each with Z blocks.
    Each block when encrypted = 12 (nonce) + 16 (tag) + 4 (id) + B (data) bytes.
    """
    print("\n" + "=" * 60)
    print("Benchmark 3: Bandwidth Overhead vs. Block Size (B)")
    print(f"  N={N}, Operations per run={num_ops}, Averaged over {num_runs} runs")
    print("=" * 60)

    results = []
    for B in block_sizes:
        run_overheads = []
        for run in range(num_runs):
            client, server = create_oram(N, B)

            # Compute tree parameters
            num_leaves = server.num_leaves
            tree_height = int(math.log2(num_leaves)) + 1  # levels on a path
            Z = server.bucket_size

            # Size of one encrypted block:
            # nonce(12) + tag(16) + serialized(4 byte id + B byte data)
            encrypted_block_size = 12 + 16 + 4 + B

            # Per access: read + write one path = 2 * tree_height * Z * encrypted_block_size
            bytes_per_access = 2 * tree_height * Z * encrypted_block_size
            total_transferred = 0
            total_payload = 0

            for op in range(num_ops):
                block_id = random.randint(0, N - 1)
                payload = os.urandom(min(B, B // 2 + 1))
                if random.random() < 0.5:
                    client.store_data(server, block_id, payload)
                else:
                    client.retrieve_data(server, block_id)
                total_transferred += bytes_per_access
                total_payload += B  # The actual data the user cares about

            overhead = total_transferred / total_payload
            run_overheads.append(overhead)

        avg_overhead = statistics.mean(run_overheads)
        results.append((B, avg_overhead))
        print(f"  B={B:>6d} bytes: bandwidth overhead = {avg_overhead:>8.2f}x")

    return results


def benchmark_stash_vs_n(n_values, block_size=256, num_ops=1000, num_runs=3):
    """
    Measure the maximum stash size observed over 1,000 continuous operations.
    """
    print("\n" + "=" * 60)
    print("Benchmark 4: Maximum Stash Size over 1,000 ops vs. N")
    print(f"  Block size B={block_size}, Operations={num_ops}, Averaged over {num_runs} runs")
    print("=" * 60)

    results = []
    for N in n_values:
        run_max_stashes = []
        for run in range(num_runs):
            client, server = create_oram(N, block_size)
            max_stash = 0

            for op in range(num_ops):
                block_id = random.randint(0, N - 1)
                if random.random() < 0.5:
                    client.store_data(server, block_id, os.urandom(block_size // 2))
                else:
                    client.retrieve_data(server, block_id)
                max_stash = max(max_stash, len(client.stash))

            run_max_stashes.append(max_stash)

        avg_max_stash = statistics.mean(run_max_stashes)
        max_max_stash = max(run_max_stashes)
        results.append((N, avg_max_stash, max_max_stash))
        print(f"  N={N:>6d}: avg max stash = {avg_max_stash:>5.1f}, worst case = {max_max_stash}")

    return results




if __name__ == "__main__":
    print("Path ORAM Performance Benchmarks")
    print("================================\n")

    # Database sizes to test
    n_values = [32, 64, 128, 256, 512]

    # Block sizes to test (bytes)
    block_sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096]

    # Run all benchmarks
    results_1 = benchmark_throughput_vs_n(n_values, block_size=256, num_ops=200, num_runs=3)
    results_2 = benchmark_latency_vs_throughput(n_values, block_size=256, num_ops=200, num_runs=3)
    results_3 = benchmark_bandwidth_vs_blocksize(block_sizes, N=128, num_ops=100, num_runs=3)
    results_4 = benchmark_stash_vs_n(n_values, block_size=256, num_ops=1000, num_runs=3)

    print("\n" + "=" * 60)
    print("All benchmarks complete!")
    print("=" * 60)
