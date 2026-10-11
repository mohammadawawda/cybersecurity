import unittest

from crashfreeORAM.crypto import DUMMY_ADDR, BlockCipher, random_key


class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.c = BlockCipher(random_key(), 64)

    def test_round_trip_and_padding(self):
        a, d = self.c.decrypt_block(self.c.encrypt_block(42, b"hello"))
        self.assertEqual(a, 42)
        self.assertEqual(d, b"hello".ljust(64, b"\x00"))

    def test_fresh_ciphertexts(self):
        self.assertNotEqual(self.c.encrypt_block(1, b"x"), self.c.encrypt_block(1, b"x"))

    def test_fixed_length_dummy_and_real(self):
        self.assertEqual(len(self.c.encrypt_block(1, b"x")), self.c.cipher_length())
        self.assertEqual(len(self.c.dummy()), self.c.cipher_length())
        self.assertEqual(self.c.decrypt_block(self.c.dummy())[0], DUMMY_ADDR)

    # pycryptodome raises ValueError ("MAC check failed") when the tag is wrong
    def test_tamper_detected(self):
        ct = bytearray(self.c.encrypt_block(1, b"x"))
        ct[20] ^= 1
        with self.assertRaises(ValueError):
            self.c.decrypt_block(bytes(ct))

    def test_wrong_key_detected(self):
        other = BlockCipher(random_key(), 64)
        with self.assertRaises(ValueError):
            other.decrypt_block(self.c.encrypt_block(1, b"x"))

    def test_too_long_data_refused(self):
        with self.assertRaises(ValueError):
            self.c.encrypt_block(1, bytes(65))


if __name__ == "__main__":
    unittest.main()
