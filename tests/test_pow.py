import unittest

from cs4160_lab1.pow import (
    WorkUnit,
    digest_for,
    encode_nonce,
    leading_zero_bits,
    satisfies_target,
    validate_identity_fields,
)


class ProofOfWorkTests(unittest.TestCase):
    def test_nonce_encoding_is_big_endian_64_bit(self):
        self.assertEqual(encode_nonce(1), b"\x00\x00\x00\x00\x00\x00\x00\x01")
        self.assertEqual(encode_nonce(256), b"\x00\x00\x00\x00\x00\x00\x01\x00")

    def test_invalid_nonce_rejected(self):
        with self.assertRaises(ValueError):
            encode_nonce(-1)
        with self.assertRaises(ValueError):
            encode_nonce(1 << 63)

    def test_prefix_uses_exact_separator_bytes(self):
        work = WorkUnit("abc@student.tudelft.nl", "https://github.com/Chevuu/cs4160")
        self.assertEqual(
            work.payload_prefix(),
            b"abc@student.tudelft.nl\nhttps://github.com/Chevuu/cs4160\n",
        )

    def test_leading_zero_bits_counts_partial_byte(self):
        self.assertEqual(leading_zero_bits(bytes.fromhex("00000f")), 20)
        self.assertEqual(leading_zero_bits(bytes.fromhex("7f")), 1)
        self.assertEqual(leading_zero_bits(bytes.fromhex("80")), 0)

    def test_target_check_for_assignment_difficulty(self):
        self.assertTrue(satisfies_target(bytes.fromhex("0000000f") + b"x" * 28))
        self.assertFalse(satisfies_target(bytes.fromhex("00000010") + b"x" * 28))

    def test_digest_depends_on_binary_nonce(self):
        prefix = WorkUnit("abc@student.tudelft.nl", "https://github.com/Chevuu/cs4160").payload_prefix()
        self.assertNotEqual(digest_for(prefix, 1), digest_for(prefix, 2))

    def test_validation_rejects_bad_fields(self):
        with self.assertRaises(ValueError):
            validate_identity_fields("person@example.com", "https://github.com/Chevuu/cs4160")
        with self.assertRaises(ValueError):
            validate_identity_fields("abc@student.tudelft.nl", "https://github.com/Chevuu/cs4160 bad")


if __name__ == "__main__":
    unittest.main()
