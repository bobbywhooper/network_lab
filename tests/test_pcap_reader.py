import ipaddress
import struct
import tempfile
import unittest
from pathlib import Path

from pcap_reader import parse_pcap, read_pcap


def make_tcp_frame(src="10.0.0.1", dst="10.0.0.2", src_port=12345, dst_port=80, payload=b"hi"):
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (5 << 12) | 0x02, 4096, 0, 0)
    ip_payload = tcp + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(ip_payload), 1, 0, 64, 6, 0,
        bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))),
    )
    return ethernet + ip_header + ip_payload


def make_udp_frame(src="10.0.0.1", dst="10.0.0.2", src_port=53000, dst_port=53, payload=b"test", fragment_field=0):
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), 1, fragment_field, 64, 17, 0,
        bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))),
    )
    return ethernet + ip_header + udp


def make_ipv6_frame(src="2001:db8::1", dst="2001:db8::2", next_header=6, payload=None):
    ethernet = bytes.fromhex("00112233445566778899aabb86dd")
    if payload is None:
        payload = struct.pack("!HHIIHHHH", 12345, 443, 1, 0, (5 << 12) | 0x02, 4096, 0, 0)
    if next_header == 0:
        payload = bytes([6, 0]) + bytes(6) + payload
    ipv6_header = struct.pack(
        "!IHBB16s16s",
        (6 << 28), len(payload), next_header, 64,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    )
    return ethernet + ipv6_header + payload


def make_pcap(packet, seconds=100, fraction=250000):
    global_header = (
        b"\xd4\xc3\xb2\xa1"
        + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    )
    record = struct.pack("<IIII", seconds, fraction, len(packet), len(packet))
    return global_header + record + packet


def make_pcapng(packet, seconds=100, microseconds=250000):
    def block(block_type, body):
        padding = bytes((-len(body)) % 4)
        body += padding
        total_length = 12 + len(body)
        return (
            struct.pack("<II", block_type, total_length)
            + body
            + struct.pack("<I", total_length)
        )

    section = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    interface = struct.pack("<HHI", 1, 0, 65535)
    packet_block = struct.pack(
        "<IIIII", 0, seconds, microseconds, len(packet), len(packet)
    ) + packet
    return (
        block(0x0A0D0D0A, section)
        + block(1, interface)
        + block(6, packet_block)
    )


class PcapReaderTests(unittest.TestCase):
    def test_parses_pcapng_enhanced_packet(self):
        events = parse_pcap(make_pcapng(make_tcp_frame()))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "10.0.0.1")
        self.assertEqual(events[0]["dst_port"], 80)
        self.assertEqual(events[0]["time"], 100.25)

    def test_rejects_truncated_pcapng_section(self):
        with self.assertRaisesRegex(ValueError, "section header"):
            parse_pcap(b"\x0a\x0d\x0d\x0a")

    def test_rejects_invalid_pcapng_byte_order_magic(self):
        data = bytearray(make_pcapng(make_tcp_frame()))
        data[8:12] = b"\x00\x00\x00\x00"
        with self.assertRaisesRegex(ValueError, "byte-order magic"):
            parse_pcap(bytes(data))

    def test_rejects_pcapng_block_length_mismatch(self):
        data = bytearray(make_pcapng(make_tcp_frame()))
        data[24:28] = struct.pack("<I", 32)
        with self.assertRaisesRegex(ValueError, "block lengths"):
            parse_pcap(bytes(data))

    def test_parses_tcp_metadata(self):
        events = parse_pcap(make_pcap(make_tcp_frame()))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "10.0.0.1")
        self.assertEqual(events[0]["dst_ip"], "10.0.0.2")
        self.assertEqual(events[0]["src_port"], 12345)
        self.assertEqual(events[0]["dst_port"], 80)
        self.assertEqual(events[0]["protocol"], "TCP")
        self.assertTrue(events[0]["tcp_syn"])
        self.assertFalse(events[0]["tcp_ack"])
        self.assertEqual(events[0]["payload_hex"], b"hi".hex())
        self.assertEqual(events[0]["payload_length"], 2)
        self.assertEqual(events[0]["time"], 100.25)

    def test_parses_ipv6_tcp_metadata(self):
        events = parse_pcap(make_pcap(make_ipv6_frame()))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["ip_version"], 6)
        self.assertEqual(events[0]["src_ip"], "2001:db8::1")
        self.assertEqual(events[0]["dst_port"], 443)
        self.assertTrue(events[0]["tcp_syn"])

    def test_parses_ipv6_hop_by_hop_extension_header(self):
        events = parse_pcap(make_pcap(make_ipv6_frame(next_header=0)))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["dst_port"], 443)

    def test_skips_ipv6_fragment_header_without_reassembly(self):
        events = parse_pcap(make_pcap(make_ipv6_frame(next_header=44, payload=bytes(8))))
        self.assertEqual(events, [])

    def test_parses_udp_metadata(self):
        events = parse_pcap(make_pcap(make_udp_frame(payload=b"\x01\x02")))
        self.assertEqual(events[0]["protocol"], "UDP")
        self.assertEqual(events[0]["src_port"], 53000)
        self.assertEqual(events[0]["dst_port"], 53)
        self.assertEqual(events[0]["payload_hex"], "0102")

    def test_skips_fragmented_ipv4_packets_without_reassembly(self):
        events = parse_pcap(make_pcap(make_udp_frame(fragment_field=0x2000)))
        self.assertEqual(events, [])

    def test_reads_capture_from_disk(self):
        with tempfile.TemporaryDirectory() as folder:
            capture_path = Path(folder) / "sample.pcap"
            capture_path.write_bytes(make_pcap(make_tcp_frame()))
            self.assertEqual(read_pcap(capture_path)[0]["dst_port"], 80)

    def test_rejects_truncated_record_header(self):
        data = make_pcap(make_tcp_frame()) + b"\\x01\\x02"
        with self.assertRaisesRegex(ValueError, "record header"):
            parse_pcap(data)

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
        frame = bytes.fromhex("00112233445566778899aabb0806") + bytes(28)
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
