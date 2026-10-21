import struct
import unittest

from dns_payload import parse_dns_payload


def make_query(name="example.com", transaction_id=0x1234):
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + question


class DnsPayloadTests(unittest.TestCase):
    def test_parses_dns_query_question(self):
        result = parse_dns_payload(make_query())
        self.assertEqual(result["transaction_id"], 0x1234)
        self.assertFalse(result["is_response"])
        self.assertTrue(result["recursion_desired"])
        self.assertEqual(result["questions"], [{"name": "example.com", "type": 1, "class": 1}])

    def test_parses_compressed_question_name(self):
        # Name points to the beginning of the question's encoded name.
        payload = make_query()
        compressed = payload[:12] + b"\xc0\x0c" + struct.pack("!HH", 28, 1)
        result = parse_dns_payload(compressed)
        self.assertEqual(result["questions"][0]["name"], "example.com")
        self.assertEqual(result["questions"][0]["type"], 28)

    def test_rejects_short_dns_header(self):
        with self.assertRaisesRegex(ValueError, "shorter than its header"):
            parse_dns_payload(b"\x00" * 11)

    def test_rejects_truncated_question_fields(self):
        payload = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x00\x00"
        with self.assertRaisesRegex(ValueError, "question fields"):
            parse_dns_payload(payload)

    def test_rejects_compression_pointer_loop(self):
        payload = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        with self.assertRaisesRegex(ValueError, "cyclic"):
            parse_dns_payload(payload)


if __name__ == "__main__":
    unittest.main()
