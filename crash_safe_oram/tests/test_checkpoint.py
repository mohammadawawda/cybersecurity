import os
import tempfile
import unittest

from crashfreeORAM import client as oc
from crashfreeORAM import wal


class TestCheckpoint(unittest.TestCase):
    def setUp(self):
        self.dir= tempfile.TemporaryDirectory()
        self.state= os.path.join(self.dir.name,"state")

    def tearDown(self):
        self.dir.cleanup()

    def test_init_then_read(self):
        oc.init_state(self.state,3,4,64)
        seq, height, bucket_size, block_size, key, pos, stash= oc.read_checkpoint(self.state)
        self.assertEqual((seq,height,bucket_size,block_size),(0,3,4,64))
        self.assertEqual(len(key),32)
        self.assertEqual(len(pos),8)
        self.assertTrue(all(0<=x<8 for x in pos))
        self.assertEqual(stash,[])
        self.assertEqual(os.path.getsize(oc.wal_path(self.state)),0)

    def test_newline_bytes_survive(self):
        # a leaf of 10 and data full of 0x0A (on windows this needs O_BINARY)
        os.makedirs(self.state)
        pos= [10]*16
        stash= [wal.Block(3,b"\n"*64)]
        payload= oc._encode_checkpoint(7,4,4,64,b"\n"*32,pos,stash)
        oc.write_checkpoint(self.state,payload)
        self.assertEqual(oc.read_checkpoint(self.state),(7,4,4,64,b"\n"*32,pos,stash))

    def test_damaged_checkpoint_is_refused(self):
        oc.init_state(self.state,3,4,64)
        with open(oc.ckpt_path(self.state),"r+b") as f:
            f.seek(20)
            b= f.read(1)
            f.seek(20)
            f.write(bytes([b[0]^1]))
        with self.assertRaises(ValueError):
            oc.read_checkpoint(self.state)

    def test_interrupted_checkpoint_keeps_the_old_one(self):
        # a crash just before the rename leaves the old checkpoint complete
        os.makedirs(self.state)
        oc.write_checkpoint(self.state,b"old")

        def crash():
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            oc.write_checkpoint(self.state,b"new",before_rename=crash)
        with open(oc.ckpt_path(self.state),"rb") as f:
            self.assertEqual(wal.unframe_all(f.read())[0],[b"old"])


if __name__ == "__main__":
    unittest.main()
