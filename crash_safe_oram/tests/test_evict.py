import unittest

from crashfreeORAM import client as oc


def bare_client(height,bucket_size):
    """
    the parameters needed for eviction test
    """
    c= object.__new__(oc.Client)
    c.height= height
    c.bucket_size= bucket_size
    c.N= 2**height
    c.pos= [oc.random_leaf(height) for _ in range(c.N)]
    c.stash= {a: bytes(16) for a in range(c.N)}
    return c


class TestEvict(unittest.TestCase):
    def test_evict_keeps_invariant(self):
        # check that every placed block is on the path of its own leaf according to path oram property
        #no bucket has more than Z slots and no block is lost or placed twice
        for _ in range(200):
            c= bare_client(6,4)
            x= oc.random_leaf(c.height)
            buckets= c.evict(x)
            self.assertEqual(len(buckets),c.height+1)
            placed= 0
            for level, blocks in enumerate(buckets):
                self.assertLessEqual(len(blocks),c.bucket_size)
                for b in blocks:
                    placed+= 1
                    shift= c.height-level
                    self.assertEqual(c.pos[b.addr]>>shift,x>>shift)
                    self.assertNotIn(b.addr,c.stash)
            self.assertEqual(placed+len(c.stash),c.N)

    def test_deepest_first(self):
        # a block whose leaf is x goes to the leaf bucket when there is a room in that path
        c= bare_client(3,4)
        c.stash= {0: bytes(16)}
        c.pos[0]= 5
        buckets= c.evict(5)
        self.assertEqual([b.addr for b in buckets[3]],[0])


if __name__ == "__main__":
    unittest.main()
