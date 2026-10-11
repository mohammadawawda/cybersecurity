import os
import random
import struct
import zlib

KIND_PLAN= 1
KIND_COMMIT= 2

# on windows os.open opens files in text mode by default and os.write turns every
# 0x0A byte into 0x0D 0x0A, which breaks every record. O_BINARY help stops that.
# on linux/mac it does not exist and it is not needed, so it is 0 there
BINARY= getattr(os,"O_BINARY",0)


class Block:

    def __init__(self, addr, data):
        self.addr = addr
        self.data = data

    def __eq__(self, other):
        if not isinstance(other, Block):
            return False
        return self.addr == other.addr and self.data == other.data


class Plan:

    def __init__(self, seq, op, addr, old_leaf, new_leaf, result, buckets, stash):
        self.seq = seq
        self.op = op
        self.addr = addr
        self.old_leaf = old_leaf
        self.new_leaf = new_leaf
        self.result = result
        self.buckets = buckets
        self.stash = stash

    def __eq__(self, other):
        if not isinstance(other, Plan):
            return False
        return (self.seq == other.seq and self.op == other.op and self.addr == other.addr
                and self.old_leaf == other.old_leaf and self.new_leaf == other.new_leaf
                and self.result == other.result and self.buckets == other.buckets
                and self.stash == other.stash)


class Record:

    def __init__(self, kind, seq, plan=None):
        self.kind = kind
        self.seq = seq
        self.plan = plan


def _enc_bytes(b):
    """
    the length of b as unsigned 32 byte int, followed by b
    """
    return struct.pack("<I",len(b))+b


def _enc_blocks(blocks):
    """
    number of blocks as unsigned 32 byte int , then each block contains address and its data
    """
    out = [struct.pack("<I", len(blocks))]
    for block in blocks:
        out.append(struct.pack("<q", block.addr))
        out.append(_enc_bytes(block.data))
    return b"".join(out)


def encode_record(record):
    """
    turns record into bytes so it can be written to the log file
    """
    out= [struct.pack("<BQ",record.kind,record.seq)]
    if record.kind==KIND_COMMIT :
        return out[0]

    p= record.plan
    op= 1 if p.op=="write" else 0
    out.append(struct.pack("<BqQQ",op,p.addr,p.old_leaf,p.new_leaf))
    out.append(_enc_bytes(p.result))
    out.append(struct.pack("<H",len(p.buckets)))
    for level in p.buckets:
        out.append(_enc_blocks(level))
    out.append(_enc_blocks(p.stash))
    return b"".join(out)


def _take(buf,offset,format):
    """
    read one struct at offset, returns the values and the new offset.
    """
    size= struct.calcsize(format)
    if offset+size>len(buf) :
        raise ValueError("record too short")
    return struct.unpack_from(format,buf,offset), offset+size


def _dec_bytes(buf,off):
    """
    read unsigned int of length 32 and then that many bytes.
    """
    (n,), off= _take(buf,off,"<I")
    if off+n>len(buf) :
        raise ValueError("record too short")
    return buf[off:off+n], off+n


def _dec_blocks(buf,off):
    """
    read unsigned int of 32bytes count and then each block (address and data)
    """
    (count,), off= _take(buf,off,"<I")
    blocks= []
    for _ in range(count):
        (addr,), off= _take(buf,off,"<q")
        data, off= _dec_bytes(buf,off)
        blocks.append(Block(addr,data))
    return blocks, off


def decode_record(buf):
    """
    from bytes to record
    """
    (kind, seq), off= _take(buf,0,"<BQ")

    if kind==KIND_COMMIT :
        return Record(kind,seq)

    if kind!=KIND_PLAN :
        raise ValueError("unknown record kind")

    (op, addr, old_leaf, new_leaf), off= _take(buf,off,"<BqQQ")
    op= "write" if op==1 else "read"
    result, off= _dec_bytes(buf,off)

    (levels,), off= _take(buf,off,"<H")
    buckets= []

    for _ in range(levels):
        level, off= _dec_blocks(buf,off)

        buckets.append(level)
    stash, off= _dec_blocks(buf,off)


    return Record(KIND_PLAN,seq,Plan(seq,op,addr,old_leaf,new_leaf,result,buckets,stash))




def frame(payload):
    """
    [length (32 unsigned bit)][crc32 (32 unsigned bit)][payload]
    """
    return struct.pack("<II",len(payload),zlib.crc32(payload))+payload

def unframe_all(data):
    """
    split data into valid payloads and stop at the first torn or corrupt frame.
    return the payloads and pointer to the last good frame
    """
    payloads= []

    off= 0

    while len(data)-off>=8 :
        n, crc= struct.unpack_from("<II",data,off)
        if len(data)-off-8<n :
            break

        payload= data[off+8:off+8+n]

        if zlib.crc32(payload)!=crc :
            break

        payloads.append(payload)
        off+= 8+n


    return payloads, off


def _write_all(fd,buffer):
    """
    write all of buffer to the file descriptor fd (os.write does not guarantee writing all of it)
    """
    view= memoryview(buffer)

    while view :
        n= os.write(fd,view)
        view= view[n:]



class Log:

    def __init__(self,path):
        """
        open the log file for adding (created if does  not exists)
        """
        self.path= path
        self.fd= os.open(path,os.O_CREAT | os.O_RDWR | os.O_APPEND | BINARY,0o600)
        self.written= 0
        self.synced_len= os.fstat(self.fd).st_size

    def append(self,record,sync):
        """
        write one framed record at the end.
        if sync we wait until it is on disk.
        """
        buf= frame(encode_record(record))
        _write_all(self.fd,buf)
        self.written+= len(buf)

        if sync :
            self.sync()

    def sync(self):
        """
        fsync: everything is guaranteed to be written so far is on disk when this returns
        """
        os.fsync(self.fd)
        self.synced_len= os.fstat(self.fd).st_size

    def cut(self):
        """
        empty the log after a checkpoint
        """
        os.ftruncate(self.fd,0)
        self.sync()

    def close(self):
        """
        sync and close (never do at a crash).
        """
        self.sync()
        os.close(self.fd)

    def simulate_power_cut(self,rng):
        """
        crash test only, we keep what was synced plus a random part of what came after
        """
        size= os.fstat(self.fd).st_size
        keep= self.synced_len+rng.randint(0,size-self.synced_len)
        os.ftruncate(self.fd,keep)
        os.fsync(self.fd)


def read_valid(path):
    """
    every intact record in the log and the length of the intact par
    stopsat the first torn or corrupt record.
    """
    try:
        with open(path,"rb") as f:
            data= f.read()
    except FileNotFoundError:
        return [], 0

    payloads, valid= unframe_all(data)
    records= []
    off= 0
    for payload in payloads:
        try:
            records.append(decode_record(payload))
        except (ValueError, struct.error):
            # crc matched but it does not decode, we treat it as the end
            valid= off
            break
        off+= 8+len(payload)
    return records, valid


def read_all(path):
    """
    return only the valid records
    """
    return read_valid(path)[0]


def cut_tail(path,valid):
    """
    remove the torn end of the log so new records are appended after the last good one, it must be called after
    a crash and before openingg the Log.
    """
    if not os.path.exists(path) :
        return
    fd= os.open(path,os.O_RDWR | BINARY)
    try:
        if os.fstat(fd).st_size!=valid :
            os.ftruncate(fd,valid)
            os.fsync(fd)
    finally:
        os.close(fd)