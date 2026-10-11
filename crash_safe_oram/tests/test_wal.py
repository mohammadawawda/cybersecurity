import os
import tempfile
import unittest

from crashfreeORAM import wal


def plan(seq):
    """
    a small plan to write and read back
    """
    return wal.Plan(seq,"write",3,5,9,b"old",
                    [[wal.Block(3,b"abc")],[],[wal.Block(7,b"xyz")]],
                    [wal.Block(11,b"s")])


class TestWAL(unittest.TestCase):
    def setUp(self):
        self.dir= tempfile.TemporaryDirectory()
        self.path= os.path.join(self.dir.name,"wal")

    def tearDown(self):
        self.dir.cleanup()

    def write_three(self):
        """
        PLAN 1, COMMIT 1, PLAN 2
        """
        log= wal.Log(self.path)
        log.append(wal.Record(wal.KIND_PLAN,1,plan(1)),True)
        log.append(wal.Record(wal.KIND_COMMIT,1),True)
        log.append(wal.Record(wal.KIND_PLAN,2,plan(2)),True)
        log.close()

    def chop(self,n):
        """
        cut the last n bytes, like a crash in the middle of the last write
        """
        with open(self.path,"rb") as f:
            data= f.read()
        with open(self.path,"wb") as f:
            f.write(data[:-n])

    def test_round_trip(self):
        self.write_three()
        records= wal.read_all(self.path)
        self.assertEqual([r.kind for r in records],[wal.KIND_PLAN,wal.KIND_COMMIT,wal.KIND_PLAN])
        self.assertEqual(records[0].plan,plan(1))

    def test_commit_is_9_bytes(self):
        self.assertEqual(len(wal.encode_record(wal.Record(wal.KIND_COMMIT,1))),9)

    def test_torn_tail_is_ignored(self):
        self.write_three()
        self.chop(20)
        records= wal.read_all(self.path)
        self.assertEqual([r.kind for r in records],[wal.KIND_PLAN,wal.KIND_COMMIT])

    def test_torn_header(self):
        # only 3 bytes of the last record's 8 byte header reached the disk
        self.write_three()
        first_two= (len(wal.frame(wal.encode_record(wal.Record(wal.KIND_PLAN,1,plan(1)))))
                    +len(wal.frame(wal.encode_record(wal.Record(wal.KIND_COMMIT,1)))))
        with open(self.path,"r+b") as f:
            f.truncate(first_two+3)
        records, valid= wal.read_valid(self.path)
        self.assertEqual(len(records),2)
        self.assertEqual(valid,first_two)

    def test_bad_crc_stops_reading(self):
        self.write_three()
        with open(self.path,"r+b") as f:
            f.seek(-3,os.SEEK_END)
            f.write(b"\xff\xff\xff")
        self.assertEqual(len(wal.read_all(self.path)),2)

    def test_append_after_torn_tail_needs_cut(self):
        # with cut_tail the new records after a torn tail can be read
        self.write_three()
        self.chop(20)
        _, valid= wal.read_valid(self.path)
        wal.cut_tail(self.path,valid)
        log= wal.Log(self.path)
        log.append(wal.Record(wal.KIND_PLAN,2,plan(2)),True)
        log.append(wal.Record(wal.KIND_COMMIT,2),True)
        log.close()
        self.assertEqual(len(wal.read_all(self.path)),4)

    def test_without_cut_new_records_are_lost(self):
        # the bug cut_tail is there for
        self.write_three()
        self.chop(20)
        log= wal.Log(self.path)
        log.append(wal.Record(wal.KIND_COMMIT,2),True)
        log.close()
        self.assertEqual(len(wal.read_all(self.path)),2)

    def test_newline_bytes_survive(self):
        # 0x0A bytes must be written as they are (on windows this needs O_BINARY to work)
        log= wal.Log(self.path)
        p= wal.Plan(1,"write",10,10,10,b"\n\r\n",[[wal.Block(10,b"\n"*64)]],[])
        log.append(wal.Record(wal.KIND_PLAN,1,p),True)
        log.close()
        self.assertEqual(wal.read_all(self.path)[0].plan,p)

    def test_cut(self):
        log= wal.Log(self.path)
        log.append(wal.Record(wal.KIND_COMMIT,1),True)
        log.cut()
        log.close()
        self.assertEqual(wal.read_all(self.path),[])

    def test_missing_file(self):
        self.assertEqual(wal.read_valid(os.path.join(self.dir.name,"nope")),([],0))


if __name__ == "__main__":
    unittest.main()
