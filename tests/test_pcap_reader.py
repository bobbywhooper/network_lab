import struct
import unittest

from pcap_reader import parse_pcap


def make_tcp_frame(src="10.0.0.1", dst="10.0.0.2", src_port=12345, dst_port=80, payload=b"hi"):
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (5 << 12) | 0x18, 4096, 0, 0)
    ip_payload = tcp + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(ip_payload), 1, 0, 64, 6, 0,
        bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))),
    )
    return ethernet + ip_header + ip_payload


def make_pcap(packet, seconds=100, fraction=250000):
    global_header = (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    record = struct.pack("<IIII", seconds, fraction, len(packet), len(packet))
    return global_header + record + packet


class PcapReaderTests(unittest.TestCase):
    def test_parses_tcp_metadata(self):
        events = parse_pcap(make_pcap(make_tcp_frame()))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "10.0.0.1")
        self.assertEqual(events[0]["dst_ip"], "10.0.0.2")
        self.assertEqual(events[0]["src_port"], 12345)
        self.assertEqual(events[0]["dst_port"], 80)
        self.assertEqual(events[0]["protocol"], "TCP")
        self.assertEqual(events[0]["payload_length"], 2)
        self.assertEqual(events[0]["time"], 100.25)

    def test_rejects_short_global_header(self):
        with self.assertRaisesRegex(ValueError, "global header"):
            parse_pcap(b"short")

    def test_rejects_truncated_packet_record(self):
        capture = make_pcap(make_tcp_frame())[:-1]
        with self.assertRaisesRegex(ValueError, "packet data"):
            parse_pcap(capture)

    def test_rejects_non_ethernet_capture(self):
        data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 101)
        with self.assertRaisesRegex(ValueError, "Ethernet"):
            parse_pcap(data)

    def test_ignores_non_ipv4_frames(self):
        frame = bytes.fromhex("00112233445566778899aabb86dd") + bytes(40)
        self.assertEqual(parse_pcap(make_pcap(frame)), [])

    def test_rejects_truncated_tcp_header(self):
        frame = bytes.fromhex("00112233445566778899aabb0800")
        ip_header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 24, 1, 0, 64, 6, 0,
            bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
        )
        self.assertRaisesRegex(ValueError, "TCP header", parse_pcap, make_pcap(frame + ip_header + b"1234"))


if __name__ == "__main__":
    unittest.main()
