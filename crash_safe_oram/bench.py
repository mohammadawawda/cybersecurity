"""
benchmark, how much does crash safety cost

runs the same random workload in 3 modes:
    nowal   no log (the original path ORAM)
    nosync  log is written but never fsynced
    sync    the real protocol  we fsync every PLAN

prints a table and saves the rows to a csv file

to run    python bench.py --spawn-server --sweep
run for one mode and one tree size L:
    python bench.py --spawn-server --mode sync -L 12
"""

import argparse
import csv
import os
import random
import shutil
import statistics
import tempfile
import time

from crashfreeORAM import client as oc
from crashfreeORAM.rpc import ClientRPC
from crashtest import spawn_server

MODES= ["nowal","nosync","sync"]
COLUMNS= ["mode","height","bucket_size","block_size","ops","avg_ms","p50_ms","p99_ms","ops_per_s",
          "wal_bytes_per_op","server_bytes_per_op","max_stash","checkpoints"]


def random_access(c,rng,block_size):
    """
    one random access, half of them writes
    """
    addr= rng.randrange(c.N)

    if rng.randrange(2)==0 :
        c.access(oc.WRITE,addr,rng.randbytes(block_size))
    else :
        c.access(oc.READ,addr)


def bench_one(args,mode,height,fill):
    """
    one new run, times args.ops accesses and returns the raw numbers
    """
    srv= ClientRPC(args.server)
    srv.reset(height,args.slot_size)
    shutil.rmtree(args.state,ignore_errors=True)
    oc.init_state(args.state,height,args.slot_size,args.block_size)

    opts= oc.Options(args.state,args.server,no_wal=(mode=="nowal"),no_sync=(mode=="nosync"),
                     checkpoint_every=args.checkpoint)
    c, _= oc.Client.open(opts)
    rng= random.Random(1)

    try:
        #  every address is written once
        if fill :
            for addr in range(c.N):
                c.access(oc.WRITE,addr,rng.randbytes(args.block_size))

        # warm up (not timed) so the stash and tree look normal when we start timing
        for _ in range(args.warm):
            random_access(c,rng,args.block_size)

        before= srv.stats()
        wal_before= c.stats.wal_bytes
        ckpt_before= c.stats.checkpoints
        latencies= []

        start= time.perf_counter()
        for _ in range(args.ops):
            t= time.perf_counter()
            random_access(c,rng,args.block_size)
            latencies.append((time.perf_counter()-t)*1000)
        total= time.perf_counter()-start

        after= srv.stats()
    finally:
        c.close()
        srv.close()
        shutil.rmtree(args.state,ignore_errors=True)

    server_bytes= (after["bytes_in"]+after["bytes_out"])-(before["bytes_in"]+before["bytes_out"])

    return {"latencies": latencies,
            "total": total,
            "wal": c.stats.wal_bytes-wal_before,
            "server": server_bytes,
            "max_stash": c.stats.max_stash,
            "checkpoints": c.stats.checkpoints-ckpt_before}


def make_row(name,height,args,runs):
    """
    puts the repeats of one config together in one row
    """
    lat= []
    total= 0
    wal= 0
    server= 0
    max_stash= 0
    checkpoints= 0

    for r in runs:
        lat+= r["latencies"]
        total+= r["total"]
        wal+= r["wal"]
        server+= r["server"]
        max_stash= max(max_stash,r["max_stash"])
        checkpoints+= r["checkpoints"]

    lat.sort()
    n= len(lat)

    return {"mode": name,
            "height": height,
            "bucket_size": args.slot_size,
            "block_size": args.block_size,
            "ops": n,
            "avg_ms": round(statistics.fmean(lat),3),
            "p50_ms": round(lat[n//2],3),
            "p99_ms": round(lat[n*99//100],3),
            "ops_per_s": round(n/total,1),
            "wal_bytes_per_op": wal//n,
            "server_bytes_per_op": server//n,
            "max_stash": max_stash,
            "checkpoints": checkpoints}


def run_config(args,height,fill,modes):
    """
    all the modes for one tree size(args.repeat times each)
    the modes take turns so a slow moment of the machine hits all of them the same
    """
    runs= {}
    for m in modes:
        runs[m]= []

    for _ in range(args.repeat):
        for m in modes:
            runs[m].append(bench_one(args,m,height,fill))

    suffix= ""
    if fill :
        suffix= "-full"

    rows= []
    for m in modes:
        rows.append(make_row(m+suffix,height,args,runs[m]))
    return rows


def print_table(rows):
    """
    prints the results, overhead is against nowal of the same tree size
    """
    # avg of nowal for every (height, full or not)
    base= {}
    for row in rows:
        if row["mode"].startswith("nowal") :
            base[(row["height"],row["mode"].endswith("-full"))]= row["avg_ms"]

    print(f"{'mode':<12s} {'height':>6s} {'avg ms':>8s} {'p50 ms':>8s} {'p99 ms':>8s} {'ops/s':>8s} "
          f"{'overhead':>9s} {'wal B/op':>9s} {'server B/op':>12s} {'max stash':>9s}")

    for row in rows:
        b= base.get((row["height"],row["mode"].endswith("-full")))
        if b :
            overhead= f"{100*(row['avg_ms']/b-1):+.0f}%"
        else :
            overhead= "-"

        print(f"{row['mode']:<12s} {row['height']:>6d} {row['avg_ms']:>8.3f} {row['p50_ms']:>8.3f} "
              f"{row['p99_ms']:>8.3f} {row['ops_per_s']:>8.1f} {overhead:>9s} {row['wal_bytes_per_op']:>9d} "
              f"{row['server_bytes_per_op']:>12d} {row['max_stash']:>9d}")


def write_csv(rows,path):
    """
    saves the rows to a csv file
    """
    with open(path,"w",newline="") as f:
        w= csv.DictWriter(f,fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)


def main():
    parser= argparse.ArgumentParser(description="how much crash safety costs")
    # 127.0.0.1 not localhost(there's a delay everytime in windows)
    parser.add_argument("--server", default="https://127.0.0.1:8080")
    parser.add_argument("--spawn-server", action="store_true", help="start server.py for the benchmark")
    parser.add_argument("--state", default=os.path.join(tempfile.gettempdir(),"oram-bench"),
                        help="client state folder")
    parser.add_argument("--mode", default="sync", choices=MODES)
    parser.add_argument("-L", type=int, default=12, help="tree height")
    parser.add_argument("--slot-size", type=int, default=4, help="bucket size")
    parser.add_argument("--block-size", type=int, default=64, help="block size")
    parser.add_argument("--ops", type=int, default=1000, help="timed accesses per run")
    parser.add_argument("--warm", type=int, default=200, help="accesses before timing")
    parser.add_argument("--checkpoint", type=int, default=200, help="checkpoint every this many accesses")
    parser.add_argument("--fill", action="store_true", help="write every address first")
    parser.add_argument("--repeat", type=int, default=3, help="runs per config")
    parser.add_argument("--sweep", action="store_true", help="all modes for every height in --heights")
    parser.add_argument("--heights", default="10,12,14,16")
    parser.add_argument("--fill-heights", default="10", help="heights with a full tree, empty for none")
    parser.add_argument("--out", default="results.csv", help="csv file")
    args= parser.parse_args()

    server_proc= None
    if args.spawn_server :
        server_proc= spawn_server(args.server,args.L,args.slot_size)

    rows= []
    try:
        if args.sweep :
            # (height, full tree or not)
            configs= []
            for h in args.heights.split(","):
                configs.append((int(h),False))
            if args.fill_heights :
                for h in args.fill_heights.split(","):
                    configs.append((int(h),True))

            for height, fill in configs:
                rows+= run_config(args,height,fill,MODES)
                if fill :
                    print(f"finished height {height} full tree",flush=True)
                else :
                    print(f"finished height {height}",flush=True)
        else :
            rows+= run_config(args,args.L,args.fill,[args.mode])
    finally:
        if server_proc is not None :
            server_proc.kill()
            server_proc.wait()

    write_csv(rows,args.out)

    print()
    print_table(rows)
    print(f"\nresults saved in {args.out}")


if __name__=="__main__":
    main()