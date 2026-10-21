import struct
import unittest

from dns_packet import build_query, decode_name, encode_name, parse_response


class DnsPacketTests(unittest.TestCase):
    def test_encode_name(self):
        self.assertEqual(
            encode_name("www.example.com"),
            b"\x03www\x07example\x03com\x00",
        )

    def test_build_query_has_one_question(self):
        packet, transaction_id = build_query("example.com", transaction_id=0x1234)

        self.assertEqual(transaction_id, 0x1234)
        self.assertEqual(struct.unpack("!HHHHHH", packet[:12]), (0x1234, 0x0100, 1, 0, 0, 0))
        self.assertTrue(packet.endswith(struct.pack("!HH", 1, 1)))

    def test_rejects_invalid_domain_label(self):
        with self.assertRaises(ValueError):
            encode_name("bad..example")

    def test_rejects_short_header(self):
        with self.assertRaises(ValueError):
            parse_response(b"short")

    def test_parses_compressed_a_answer_and_checks_id(self):
        transaction_id = 0x4321
        flags = 0x8180  # Response, recursion desired/available, no error.
        header = struct.pack("!HHHHHH", transaction_id, flags, 1, 1, 0, 0)
        question = encode_name("example.com") + struct.pack("!HH", 1, 1)
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 300, 4)
            + b"\x93\x184\x34"
        )
        packet = header + question + answer

        result = parse_response(packet, expected_transaction_id=transaction_id)

        self.assertEqual(result["questions"][0]["name"], "example.com")
        self.assertEqual(result["answers"][0]["value"], "147.24.52.52")
        self.assertEqual(result["answers"][0]["ttl"], 300)

        with self.assertRaises(ValueError):
            parse_response(packet, expected_transaction_id=0x9999)

    def test_decode_name_rejects_pointer_outside_packet(self):
        with self.assertRaises(ValueError):
            decode_name(b"\xc0\x10", 0)


if __name__ == "__main__":
    unittest.main()
