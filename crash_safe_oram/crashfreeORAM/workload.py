"""
read/write operations
"""

import random


class Op:
    def __init__(self,seq,write,addr,data):
        """
        one operation (data is null for read).
        """
        self.seq= seq
        self.write= write
        self.addr= addr
        self.data= data


def gen(seed,num_of_addresses,block_size,n):
    """
    returns n operations (about half writes on the first 64 addresses.)
    """
    r= random.Random(seed)
    ops= []
    for seq in range(1,n+1):
        addr= r.randrange(min(num_of_addresses,64))
        # r==0 means write
        if r.randrange(2)==0 :
            #we want to produce a 64 bytes block data and be able to recover and check it with the method expected
            data= seed.to_bytes(8,"little")+seq.to_bytes(8,"little")+r.randbytes(block_size-16)
            ops.append(Op(seq,True,addr,data))
        else :
            ops.append(Op(seq,False,addr,None))
    return ops


def expected(ops,block_size,skip=0):
    """
    final value of every touched address and skip when seq == skip
    """
    values= {}
    for op in ops:
        if op.seq==skip :
            continue
        if op.addr not in values :
            values[op.addr]= bytes(block_size)
        if op.write :
            values[op.addr]= op.data
    return values