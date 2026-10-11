"""
crash the client on purpose at a random point of a random access then recover, and check
that the data is right and recovery leaks nothing


the part that crashes runs in a child process using multiprocessing and everything else
runs here in the parent.

half of the runs are a power cut instead of a process crash
half of the runs also crash a second time, in the middle of the recovery write

run it with new server:(needs certs/cert.pem and certs/key.pem)
    python crashtest.py --spawn-server --runs 300 --ops 60 -L 10
or with a server that is already running:
    python server.py -L 10
    python crashtest.py --runs 300 --ops 60 -L 10
"""

import argparse
import multiprocessing
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from urllib.parse import urlparse

from crashfreeORAM import client as oc
from crashfreeORAM import workload
from crashfreeORAM.rpc import ClientRPC

HERE= os.path.dirname(os.path.abspath(__file__))

# spawn = every child is a brand new python process, the same on windows, linux and mac.
# (fork, the linux default, would copy the parent's memory, open files and connections into the child)
MP= multiprocessing.get_context("spawn")


class RunFailed(Exception):
    """
    one crash run found a problem
    """


def do_op(c,op):
    """
    run one operation on the client
    """
    if op.write :
        c.access(oc.WRITE,op.addr,op.data)
    else :
        c.access(oc.READ,op.addr)


def run_child(state_dir,server,seed,ops,ckpt,crash,conn):
    """
    run the workload until the client crashes on purpose

    """
    # remove client's crash line when it dies on purpose
    sys.stderr= open(os.devnull,"w")
    try:
        # start recovery or a fresh start for the client
        c, _= oc.Client.open(oc.Options(state_dir,server,checkpoint_every=ckpt,crash=crash))

        # important note, using gen with the same seed rebuilds the same sequence
        #we did so intentionally to reproduce the sequence using the psuedo random number generator
        # with the same seed, which results in the same output
        for op in workload.gen(seed,c.N,c.block_size,ops):
            do_op(c,op)
            conn.send(("ack",op.seq))
        # we only get here if the crash never happened and the parent reports it
        c.close()
    except Exception:
        conn.send(("error",traceback.format_exc()))
        sys.exit(1)


def recover_child(state_dir,server,ckpt,conn):
    """
    runs in child process, it open the client that runs the recovery and crash in the middle
    of the recovery write, if there is nothing to redo it just closes
    """
    sys.stderr= open(os.devnull,"w")
    try:
        crash= oc.CrashSpec(oc.CRASH_RECOVERY_WRITE,0)
        c, _= oc.Client.open(oc.Options(state_dir,server,checkpoint_every=ckpt,crash=crash))
        c.close()
    except Exception:
        conn.send(("error",traceback.format_exc()))
        sys.exit(1)


def run_in_child(target,args):
    """
    runs in the parent.
    it starts one child and collects what the child reports, then waits for it to end.
    """
    reader, writer= MP.Pipe(duplex=False)
    #add the writer(child's means of communication with the parent)
    #into the arguments so the child can send the parent msgs about the crash
    #since the buffer of the pipe lives inside the kernel and survives the process crash

    p= MP.Process(target=target,args=args+(writer,))
    p.start()
    # close our copy of the sending end
    # so recv sees the end once the child is gone
    writer.close()

    acked= 0
    error= None
    while True:
        try:
            kind, value= reader.recv()
        except EOFError:
            break
        if kind=="ack" :
            acked= value
        else :
            error= value
    p.join()
    reader.close()
    return p.exitcode, acked, error


def recover_and_check(args,seed,acked,finish):
    """
    runs in the parent, it recovers and checks the data
    """
    # open the client with the state that the child left behind
    c, info= oc.Client.open(oc.Options(args.state,args.server,checkpoint_every=args.checkpoint))
    try:
        #the number of server requests including recovery
        after_open= c.trace_len()

        ops= workload.gen(seed,c.N,c.block_size,args.ops)
        if finish :
            for op in ops:
                if op.seq>=acked+2 :
                    do_op(c,op)

        without= workload.expected(ops,c.block_size,skip=acked+1)   # the interrupted op did not happen
        with_all= workload.expected(ops,c.block_size)               # it did happen
        zero= bytes(c.block_size)
        problems= []
        for addr in sorted(set(without)|set(with_all)):
            got= c.access(oc.READ,addr)
            want1= without.get(addr,zero)
            want2= with_all.get(addr,zero)
            if got!=want1 and got!=want2 :
                problems.append(f"got must equal one of the two allowed values. with operation ack+1 or without")
        return info, after_open, problems
    finally:
        c.close()


def crash_run(args,srv,point,crash_seq,power,double,seed):
    """
    one run: fresh state, run and crash, maybe crash again during the recovery,
    then recover here and check the data, the trace and a clean reopen

    returns acked, redone, how many requests the recovery made and if the second crash happened
    raises RunFailed if something is wrong
    """
    #new server tree and client state
    srv.reset(args.L,args.slot_size)
    shutil.rmtree(args.state,ignore_errors=True)
    oc.init_state(args.state,args.L,args.slot_size,args.block_size)

    # run the workload in child and crash it
    crash= oc.CrashSpec(point,crash_seq,power)
    code, acked, error= run_in_child(run_child,(args.state,args.server,seed,args.ops,args.checkpoint,crash))
    if code!=oc.CRASH_EXIT_CODE :
        raise RunFailed(f"got crash that is not expected in the child process")

    #  maybe crash again, in the middle of the recovery write
    double_crashed= False
    if double :
        code, _, error= run_in_child(recover_child,(args.state,args.server,args.checkpoint))
        if code==oc.CRASH_EXIT_CODE :
            double_crashed= True
        elif code!=0 :   #  if code=0 there's nothing to redo, that's fine
            raise RunFailed(f"unplanned crash!")

    # what the server saw so far, and which leaves the recovery may write
    events= srv.trace()["events"]
    before= len(events)
    if power :
        # a power cut can also lose the COMMIT of the access before, we redo that one
        # both leaves were already shown to the server by their reads
        reads = []
        for e in events:
            if e["op"] == "read":
                reads.append(e["leaf"])
        allowed= set(reads[-2:])
    else :
        allowed= {events[-1]["leaf"]} if events else set()

    #recover the client in the parent and finish the workloadand checks the data.
    info, after_open, problems= recover_and_check(args,seed,acked,finish=True)
    if problems :
        raise RunFailed("wrong data after recovery\n"+"\n".join(problems))

    #the recovery made at most one write to an allowed leaf
    recovery_events= srv.trace()["events"][before:after_open]
    for e in recovery_events:
        if e["op"]!="write" or e["leaf"] not in allowed :
            raise RunFailed(f"recovery touched an illegal path")
    if len(recovery_events)>1 :
        raise RunFailed(f"recovery made more than 1 request")
    if info.redone!=(len(recovery_events)>0) :
        raise RunFailed(f"redone and requests dont match")

    # after the recovery must be fine too
    info2, _, problems= recover_and_check(args,seed,acked,finish=False)
    if problems :
        raise RunFailed("wrong data after a clean reopen\n"+"\n".join(problems))
    if info2.redone :
        raise RunFailed("a clean reopen still had something to redo")

    return acked, info.redone, len(recovery_events), double_crashed


def spawn_server(url,height,bucket_size):
    """
    start server.py in the background (https with certs/cert.pem and certs/key.pem)
    and wait until it answers
    """
    proc= subprocess.Popen([sys.executable,os.path.join(HERE,"server.py"),
                            "--port",str(urlparse(url).port),"-L",str(height),"--slot-size",str(bucket_size),
                            "--cert",os.path.join(HERE,"certs","cert.pem"),
                            "--key",os.path.join(HERE,"certs","key.pem")],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for _ in range(100):
        if proc.poll() is not None :
            sys.exit("the server stopped instantly")
        try:
            r= ClientRPC(url)
            r.params()
            r.close()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    sys.exit("the server did not answer")


def main():
    parser= argparse.ArgumentParser(description="crash test for the crash safe path ORAM")
    # we use 127.0.0.1 and not localhost on win
    parser.add_argument("--server", default="https://127.0.0.1:8080")
    parser.add_argument("--spawn-server", action="store_true", help="start server.py for the test")
    parser.add_argument("--state", default=os.path.join(tempfile.gettempdir(),"oram-crashtest"))
    parser.add_argument("-L", type=int, default=8, help="tree height")
    parser.add_argument("--slot-size", type=int, default=4, help="bucket size")
    parser.add_argument("--block-size", type=int, default=64, help="block size, at least 16")
    parser.add_argument("--runs", type=int, default=50)
    parser.add_argument("--ops", type=int, default=40, help="workload length per run")
    parser.add_argument("--checkpoint", type=int, default=10, help="checkpoint every this many accesses (small so it happens a lot)")
    parser.add_argument("--power", type=float, default=0.5, help="part of the runs that are a power cut")
    parser.add_argument("--seed", type=int, default=time.time_ns()%2**31)
    args= parser.parse_args()

    server_proc= None
    if args.spawn_server :
        server_proc= spawn_server(args.server,args.L,args.slot_size)
    srv= ClientRPC(args.server)
    rng= random.Random(args.seed)
    print(f"starting crash test with runs={args.runs} ops={args.ops} L={args.L} slot_size={args.slot_size} block_size={args.block_size} "
          f"checkpoint every {args.checkpoint} power cut part={args.power} seed={args.seed}", flush=True)

    points= list(oc.CRASH_POINTS)
    if args.ops<args.checkpoint :   # no checkpoint ever happens, so it can't crash there
        points.remove(oc.CRASH_MID_CHECKPOINT)
    # counters for each crash point, all start at 0
    stats = {}
    for p in points:
        stats[p] = {"runs": 0, "power": 0, "redone": 0, "double": 0, "failed": 0}
    failures= 0

    try:
        for run in range(1,args.runs+1):
            point= rng.choice(points)
            crash_seq= 1+rng.randrange(args.ops)
            if point==oc.CRASH_MID_CHECKPOINT :   # only happens on checkpoint boundaries
                crash_seq= (1+rng.randrange(args.ops//args.checkpoint))*args.checkpoint
            power= rng.random()<args.power
            double= rng.randrange(2)==0
            seed= args.seed+run
            kind= "power" if power else "proc"
            s= stats[point]
            s["runs"]+= 1
            s["power"]+= power

            try:
                acked, redone, n_events, double_crashed= crash_run(args,srv,point,crash_seq,power,double,seed)
            except RunFailed as e:
                failures+= 1
                s["failed"]+= 1
                print(f"run {run:3d}  {point:<15s} seq={crash_seq:<3d} {kind:5s} failed: {e}",flush=True)
                continue
            except Exception:
                failures+= 1
                s["failed"]+= 1
                print(
                    f"run {run:3d}  {point:<15s} seq={crash_seq:<3d} {kind:5s} failed with unexpected error:\n{traceback.format_exc()}",
                    flush=True)
                continue

            s["redone"]+= redone
            s["double"]+= double_crashed
            print(f"run {run:3d}  {point:<15s} seq={crash_seq:<3d} acked={acked:<3d} {kind:5s} "
                  f"double={str(double_crashed):<5s} redone={str(redone):<5s} recovery requests={n_events}  passed",flush=True)
    finally:
        srv.close()
        if server_proc is not None :
            server_proc.kill()
            server_proc.wait()

    print()
    print(f"{'crash point':<16s} {'runs':>5s} {'power cut':>9s} {'redone':>7s} {'double crash':>12s} {'failed':>6s}")
    for p in points:
        s = stats[p]
        print(f"{p:<16s} {s['runs']:5d} {s['power']:9d} {s['redone']:7d} {s['double']:12d} {s['failed']:6d}")
    if failures :
        print(f"\nfailed: {failures} of {args.runs} runs")
        sys.exit(1)
    print(f"\nall {args.runs} runs passed")


# we need this so a spawned child does not run main()
if __name__=="__main__":
    main()
