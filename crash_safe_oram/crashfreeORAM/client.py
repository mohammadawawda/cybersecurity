
import os
import random
import secrets
import struct
import sys

from . import wal
from .crypto import DUMMY_ADDR, BlockCipher, random_key

from .rpc import ClientRPC

READ= "read"
WRITE= "write"

# crash points in the  order they happen inside an access
CRASH_BEFORE_READ= "before_read"
CRASH_AFTER_READ= "after_read"
CRASH_AFTER_LOG= "after_log"
CRASH_MID_WRITE= "mid_write"
CRASH_AFTER_WRITE= "after_write"
CRASH_AFTER_COMMIT= "after_commit"
CRASH_MID_CHECKPOINT= "mid_checkpoint"

# crash point inside recovery
CRASH_RECOVERY_WRITE= "recovery_write"

CRASH_POINTS= [CRASH_BEFORE_READ,CRASH_AFTER_READ,CRASH_AFTER_LOG,CRASH_MID_WRITE,
               CRASH_AFTER_WRITE,CRASH_AFTER_COMMIT,CRASH_MID_CHECKPOINT]

CRASH_EXIT_CODE= 3

#the first 8 bytes of every checkpiont
CHECKPOINT_HEADER= b"ORAMCKP1"


def random_leaf(L):
    """
    random leaf from 0 to 2^L - 1, from secrets so the server can't predict it
    """
    return secrets.randbits(L)


def ckpt_path(state_dir):
    """
    path of the checkpoint file
    """
    return os.path.join(state_dir,"checkpoint")


def wal_path(state_dir):
    """
    path of the log file
    """
    return os.path.join(state_dir,"wal")

class CrashSpec:

    def __init__(self,point,seq,power_cut=False):
        """
        where to crash on purpose


        point: crash point name, one of the CRASH_ constants
        seq: access number to crash at, 0 means any access
        power_cut: also drop the log bytes written after the last fsync
        """
        self.point= point
        self.seq= seq
        self.power_cut= power_cut

class Options:

    def __init__(self,state_dir,server,no_wal=False,no_sync=False,checkpoint_every=200,crash=None):
        """
        how the client runs.


        state_dir: folder with the checkpoint and the log
        server: server url (localhost for example)
        no_wal: no log at all
        no_sync: write the log but never fsync
        checkpoint_every: write a checkpoint every this many accesses
        crash: a CrashSpec or  None for no crash
        """
        self.state_dir= state_dir
        self.server= server
        self.no_wal= no_wal
        self.no_sync= no_sync
        self.checkpoint_every= checkpoint_every
        self.crash= crash

class Stats:

    def __init__(self):
        """
        counters for the benchmark, all start at 0

        accesses: how many accesses finished
        wal_bytes: bytes written to the log
        checkpoints: how many checkpoints were written
        max_stash: the biggest the stash got
        """
        self.accesses= 0
        self.wal_bytes= 0
        self.checkpoints= 0
        self.max_stash= 0

class RecoveryInfo:

    def __init__(self):
        """
        what open() had to do after a restart

        replayed: how many PLAN records were replayed from the log
        redone: True if an unfinished access had to be written again
        seq: which access was redone
        op: its operation (read or write)
        addr: its address
        leaf: the path that was written again
        """
        self.replayed= 0
        self.redone= False
        self.seq= 0
        self.op= ""
        self.addr= 0
        self.leaf= 0

class NeedsRecovery(Exception):
    """
    an access failed halfway (an actual error, not a crash).
    memory may be ahead of the server now, so this client refuses more accesses,
    reopen it and open() finishes or drops the access from the log.
    """

def _encode_checkpoint(seq,height,bucket_size,block_size,key,pos,stash):
    """
    everything the client has to remember, as bytes

    seq: last finished access
    tree height, bucket size, block size
    key: the aes key
    pos: the position map, one leaf per address
    stash: list of wal.Block
    """
    out= [CHECKPOINT_HEADER]
    out.append(struct.pack("<QIII",seq,height,bucket_size,block_size))
    out.append(wal._enc_bytes(key))
    out.append(struct.pack(f"<{len(pos)}Q",*pos))
    out.append(wal._enc_blocks(stash))
    return b"".join(out)


def _decode_checkpoint(buf):
    """
    bytes back into the client state, the reverse of _encode_checkpoint
    returns seq, height, bucket_size, block_size, key, pos, stash
    """
    if buf[:len(CHECKPOINT_HEADER)] != CHECKPOINT_HEADER:
        raise ValueError("not a checkpoint")
    off = len(CHECKPOINT_HEADER)
    (seq, height, bucket_size, block_size), off = wal._take(buf, off, "<QIII")
    key, off = wal._dec_bytes(buf, off)
    pos, off = wal._take(buf, off, f"<{2 ** height}Q")
    stash, off = wal._dec_blocks(buf, off)
    return seq, height, bucket_size, block_size, key, list(pos), stash

def write_checkpoint(state_dir,payload,before_rename=None):
    """
    replace the checkpoint file safely: a crash at any moment leaves
    either the whole old file or the whole new one

    state_dir: the client state folder
    payload: the bytes from _encode_checkpoint
    before_rename: optional function called just before the rename (crash tests)
    """
    # write the new checkpoint to a temp file and make sure it is on disk

    tmp= ckpt_path(state_dir)+".tmp"

    fd= os.open(tmp,os.O_CREAT | os.O_TRUNC | os.O_WRONLY | wal.BINARY,0o600)
    try:
        wal._write_all(fd,wal.frame(payload))

        os.fsync(fd)
    finally:
        os.close(fd)



    # the mid_checkpoint crash point
    if before_rename is not None :

        before_rename()
    # swap it in, all at once
    os.replace(tmp,ckpt_path(state_dir))

    # make the rename itself durable (windows can't open a folder, so skip there)
    try:
        dir_fd= os.open(state_dir,os.O_RDONLY)
        try:

            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass

def read_checkpoint(state_dir):
    """
    load the checkpoint, raise ValueError if it is damaged
    returns seq, height, bucket_size, block_size, key, pos, stash
    """
    with open(ckpt_path(state_dir),"rb") as f:
        data= f.read()
    payloads, valid= wal.unframe_all(data)

    if len(payloads)!=1 or valid!=len(data) :
        raise ValueError("checkpoint is corrupt")

    return _decode_checkpoint(payloads[0])


def init_state(state_dir,height,bucket_size,block_size):
    """
    a new client state: random positions, new key, empty stash, empty log

    state_dir: folder to create it in
    height, bucket_size, block_size: the tree and block sizes
    """
    os.makedirs(state_dir,mode=0o700,exist_ok=True)

    pos= [random_leaf(height) for _ in range(2**height)]

    write_checkpoint(state_dir,_encode_checkpoint(0,height,bucket_size,block_size,random_key(),pos,[]))
    fd= os.open(wal_path(state_dir),os.O_CREAT | os.O_TRUNC | os.O_WRONLY | wal.BINARY,0o600)


    os.close(fd)

class Client:

    def __init__(self,options):
        """
        load the client state from the checkpoint and connect to the server
        use Client.open(options) instead of calling this directly

        options: an Options object
        """
        if options.checkpoint_every<=0 :
            options.checkpoint_every= 200
        try:
            seq,height,bucket_size,block_size,key,pos,stash= read_checkpoint(options.state_dir)
        except FileNotFoundError:
            raise RuntimeError(f"no client state in {options.state_dir}, call init_state first")

        self.opts= options
        self.height= height
        self.bucket_size= bucket_size
        self.block_size= block_size
        self.N= 2**height
        self.key= key
        self.cipher= BlockCipher(key,block_size)
        self.pos= pos
        self.stash= {block.addr: block.data for block in stash}
        self.seq= seq
        self.srv= ClientRPC(options.server)
        self.log= None
        self.stats= Stats()
        self._broken= False
        self._crash_rng= random.Random()

        # the server must hold a tree of the same shape
        p= self.srv.params()
        if p["L"]!=height or p["Z"]!=bucket_size :
            raise RuntimeError(f"server has L={p['L']} Z={p['Z']}, client state has L={height} Z={bucket_size}")

    @classmethod
    def open(cls,options):
        """
        load the state, recover from a crash if needed, returns (client, RecoveryInfo)
        """
        client= cls(options)
        info= RecoveryInfo()
        if options.no_wal :
            return client, info

        #read the valid records and cut off a torn end before appending again
        path= wal_path(options.state_dir)
        records, valid= wal.read_valid(path)

        wal.cut_tail(path,valid)

        # replay: apply every PLAN after the checkpoint and remember one without a COMMIT
        checkpoint_seq= client.seq
        pending= None
        for record in records:
            if record.seq<=checkpoint_seq :
                continue  # already inside the checkpoint
            if record.kind==wal.KIND_PLAN :

                if record.seq!=client.seq+1 :

                    raise RuntimeError(f"log: expected seq {client.seq+1}, got {record.seq}")
                plan= record.plan
                client.pos[plan.addr]= plan.new_leaf    # memory only, nevr sent
                client.stash= {b.addr: b.data for b in plan.stash}
                client.seq= plan.seq


                pending= plan
                info.replayed+= 1

            elif record.kind==wal.KIND_COMMIT :
                if pending is not None and pending.seq==record.seq :
                    pending= None

        # open log then finish the unfinished access if there is one
        client.log= wal.Log(path)
        if pending is not None :
            client.redo(pending)
            info.redone= True
            info.seq= pending.seq
            info.op= pending.op
            info.addr= pending.addr
            info.leaf= pending.old_leaf
        return client, info


    def close(self):
        """
        normal exit: sync and close the log, close the connection
        """
        if self.log is not None :
            self.log.close()
            self.log= None
        self.srv.close()

    def redo(self,plan):
        """
        write the path of an unfinished access again, then COMMIT it.
        only old_leaf goes to the server
        """
        self.write_path(plan.old_leaf,plan.buckets,CRASH_RECOVERY_WRITE,plan.seq)
        self.log.append(wal.Record(wal.KIND_COMMIT,plan.seq),not self.opts.no_sync)

    def access(self,op,addr,data=None):
        """
        one oblivious read or write, returns the value the block had before it

        op: READ or WRITE
        addr: which block
        data: the new value for a write
        """
        if self._broken :
            raise NeedsRecovery("an earlier access failed halfway, reopen the client")
        if not 0<=addr<self.N :
            raise ValueError("address out of range")
        if op==WRITE and len(data)>self.block_size :
            raise ValueError("data is longer than the block size")
        seq= self.seq+1
        self.crash_if(CRASH_BEFORE_READ,seq)

        #read the path the block is on now and pick where it goes next
        old_leaf= self.pos[addr]
        new_leaf= random_leaf(self.height)
        for bucket in self.srv.read_path(old_leaf):
            for ct in bucket:
                if ct is None :
                    continue
                a, d= self.cipher.decrypt_block(ct)
                if a!=DUMMY_ADDR :
                    self.stash[a]= d
        self.crash_if(CRASH_AFTER_READ,seq)

        try:
            #do the read/write in the stash thewn move the block then decide what goes back
            result= self.stash.get(addr,bytes(self.block_size))
            if op==WRITE :
                self.stash[addr]= data+bytes(self.block_size-len(data))
            self.pos[addr]= new_leaf

            self.stats.max_stash= max(self.stats.max_stash,len(self.stash))


            buckets= self.evict(old_leaf)

            #PLAN: the whole result goes to disk before the server is touched
            if not self.opts.no_wal :
                rest= [wal.Block(a,d) for a,d in self.stash.items()]
                plan= wal.Plan(seq,op,addr,old_leaf,new_leaf,result,buckets,rest)
                before= self.log.written
                self.log.append(wal.Record(wal.KIND_PLAN,seq,plan),not self.opts.no_sync)
                self.stats.wal_bytes+= self.log.written-before
            self.crash_if(CRASH_AFTER_LOG,seq)

            # write the same path back
            self.write_path(old_leaf,buckets,CRASH_MID_WRITE,seq)
            self.crash_if(CRASH_AFTER_WRITE,seq)

            #COMMIT, no fsync needed
            if not self.opts.no_wal :
                self.log.append(wal.Record(wal.KIND_COMMIT,seq),False)
        except Exception as e:
            # memory is ahead of the server
            self._broken= True
            raise NeedsRecovery(f"access {seq} failed: {e}") from e

        self.seq= seq
        self.stats.accesses+= 1
        self.crash_if(CRASH_AFTER_COMMIT,seq)

        # checkpoint every checkpoint_every accesses
        if not self.opts.no_wal and seq%self.opts.checkpoint_every==0 :
            self.checkpoint(seq)
        return result

    def evict(self,leaf):
        """
        greedy eviction: from the leaf to the root, fill each bucket with up to Z
        stash blocks that are allowed there
        returns the buckets root first
        """
        buckets= []
        for level in range(self.height,-1,-1):
            shift= self.height-level
            bucket= []
            for a in list(self.stash):
                if len(bucket)==self.bucket_size :
                    break
                if self.pos[a]>>shift==leaf>>shift :
                    bucket.append(wal.Block(a,self.stash.pop(a)))
            buckets.append(bucket)
        buckets.reverse()
        return buckets

    def write_path(self,leaf,buckets,crash_point,seq):
        """
        encrypt every bucket and fill it with dummies up to Z slots so they all look
        the same and then send the whole path

        crash_point, seq: where a crash test may cut this write short
        """
        encrypted= []
        for bucket in buckets:
            slots= [self.cipher.encrypt_block(b.addr,b.data) for b in bucket]
            slots+= [self.cipher.dummy() for _ in range(self.bucket_size-len(bucket))]
            encrypted.append(slots)

        if self.crashing(crash_point,seq) :
            # send only part of the path so the server really is half updated
            k= self._crash_rng.randint(1,self.height)
            self.srv.write_path(leaf,0,encrypted[:k])
            self.crash(crash_point,seq)
        self.srv.write_path(leaf,0,encrypted)

    def checkpoint(self,seq):
        """
        save the whole state, then empty the log
        """
        rest= [wal.Block(a,d) for a,d in self.stash.items()]
        payload= _encode_checkpoint(seq,self.height,self.bucket_size,self.block_size,self.key,self.pos,rest)
        write_checkpoint(self.opts.state_dir,payload,
                         before_rename=lambda: self.crash_if(CRASH_MID_CHECKPOINT,seq))
        self.stats.checkpoints+= 1
        self.log.cut()

    def crashing(self,point,seq):
        """
        True if the crash test asked to crash here
        """
        c= self.opts.crash
        return c is not None and c.point==point and c.seq in (0,seq)

    def crash_if(self,point,seq):
        """
        crash here if the crash test asked for it
        """
        if self.crashing(point,seq) :
            self.crash(point,seq)

    def crash(self,point,seq):
        """
        die right now with no cleanup like a real crash.
        os._exit skips finally blocks, with blocks and log.close() (sys.exit would run them)
        the crash test runs this in a child process, so only that process dies
        """
        if self.opts.crash.power_cut and self.log is not None :
            self.log.simulate_power_cut(self._crash_rng)
        sys.stdout.flush()
        sys.stderr.write(f"CRASH {point} seq={seq}\n")
        sys.stderr.flush()
        os._exit(CRASH_EXIT_CODE)

    def stash_len(self):
        """
        how many blocks are in the stash right now
        """
        return len(self.stash)

    def trace_len(self):
        """
        how many requests the server has seen so far
        """
        return self.srv.trace_len()