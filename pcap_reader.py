"""Read classic PCAP files and extract basic Ethernet/IPv4 TCP/UDP metadata.

This intentionally small reader uses only the standard library. It does not
reassemble IP fragments or TCP streams, and it supports Ethernet link layers
with IPv4 packets only.
"""

import ipaddress
import struct


GLOBAL_HEADER_SIZE = 24
RECORD_HEADER_SIZE = 16
MAX_CAPTURED_PACKET_SIZE = 64 * 1024 * 1024

# magic bytes: (byte order, timestamp resolution)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
ETHERNET = 1
IPV4_ETHERTYPE = 0x0800
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}


def _parse_ethernet_ipv4(packet, timestamp):
    """Return transport metadata for supported IPv4 packets, or None."""
    if len(packet) < 14:
        raise ValueError("Truncated Ethernet header")

    ethertype = struct.unpack("!H", packet[12:14])[0]
    offset = 14

    # VLAN tags insert a 4-byte tag between the Ethernet and IP headers.
    while ethertype in VLAN_ETHERTYPES:
        if len(packet) < offset + 4:
            raise ValueError("Truncated Ethernet VLAN tag")
        ethertype = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
        offset += 4

    if ethertype != IPV4_ETHERTYPE:
        return None

    if len(packet) < offset + 20:
        raise ValueError("Truncated IPv4 header")

    first_byte = packet[offset]
    version = first_byte >> 4
    header_length = (first_byte & 0x0F) * 4
    if version != 4 or header_length < 20:
        raise ValueError("Invalid IPv4 header")
    if len(packet) < offset + header_length:
        raise ValueError("Truncated IPv4 options")

    total_length = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
    if total_length < header_length:
        raise ValueError("Invalid IPv4 total length")
    if len(packet) < offset + total_length:
        raise ValueError("Truncated IPv4 packet")

    fragment_field = struct.unpack("!H", packet[offset + 6:offset + 8])[0]
    fragment_offset = fragment_field & 0x1FFF
    if fragment_offset:
        # Non-initial fragments do not begin with a TCP/UDP header.
        return None

    protocol = packet[offset + 9]
    src_ip = str(ipaddress.IPv4Address(packet[offset + 12:offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(packet[offset + 16:offset + 20]))
    transport_start = offset + header_length
    ip_payload_end = offset + total_length

    if protocol == 6:  # TCP
        if ip_payload_end - transport_start < 20:
            raise ValueError("Truncated TCP header")
        src_port, dst_port = struct.unpack("!HH", packet[transport_start:transport_start + 4])
        tcp_header_length = (packet[transport_start + 12] >> 4) * 4
        if tcp_header_length < 20 or transport_start + tcp_header_length > ip_payload_end:
            raise ValueError("Invalid or truncated TCP options")
        payload_length = ip_payload_end - transport_start - tcp_header_length
        transport = "TCP"
    elif protocol == 17:  # UDP
        if ip_payload_end - transport_start < 8:
            raise ValueError("Truncated UDP header")
        src_port, dst_port, udp_length = struct.unpack(
            "!HHH", packet[transport_start:transport_start + 6]
        )
        if udp_length < 8 or transport_start + udp_length > ip_payload_end:
            raise ValueError("Invalid or truncated UDP datagram")
        payload_length = udp_length - 8
        transport = "UDP"
    else:
        return None

    return {
        "time": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": transport,
        "payload_length": payload_length,
        "ip_length": total_length,
    }


def parse_pcap(data):
    """Parse classic PCAP bytes into packet metadata dictionaries."""
    if len(data) < GLOBAL_HEADER_SIZE:
        raise ValueError("PCAP file is shorter than its 24-byte global header")

    magic = data[:4]
    if magic not in PCAP_MAGICS:
        raise ValueError("Unsupported PCAP magic or file format")
    byte_order, timestamp_resolution = PCAP_MAGICS[magic]

    major, minor, _timezone, _sigfigs, snaplen, network = struct.unpack(
        byte_order + "HHIIII", data[4:GLOBAL_HEADER_SIZE]
    )
    if (major, minor) != (2, 4):
        raise ValueError(f"Unsupported PCAP version: {major}.{minor}")
    if snaplen == 0 or snaplen > MAX_CAPTURED_PACKET_SIZE:
        raise ValueError("Invalid PCAP snapshot length")
    if network != ETHERNET:
        raise ValueError("Only Ethernet link-layer PCAP files are supported")

    offset = GLOBAL_HEADER_SIZE
    events = []

    while offset < len(data):
        if len(data) - offset < RECORD_HEADER_SIZE:
            raise ValueError("Truncated PCAP packet record header")

        seconds, fraction, captured_length, original_length = struct.unpack(
            byte_order + "IIII", data[offset:offset + RECORD_HEADER_SIZE]
        )
        offset += RECORD_HEADER_SIZE

        if fraction >= timestamp_resolution:
            raise ValueError("PCAP timestamp fraction is out of range")
        if captured_length > snaplen or captured_length > MAX_CAPTURED_PACKET_SIZE:
            raise ValueError("PCAP captured packet length exceeds configured limits")
        if original_length < captured_length:
            raise ValueError("PCAP original length is smaller than captured length")
        if offset + captured_length > len(data):
            raise ValueError("Truncated PCAP packet data")

        packet = data[offset:offset + captured_length]
        offset += captured_length
        timestamp = seconds + fraction / timestamp_resolution
        event = _parse_ethernet_ipv4(packet, timestamp)
        if event is not None:
            events.append(event)

    return events


def read_pcap(filename):
    """Read a classic PCAP file from disk and return supported packet events."""
    with open(filename, "rb") as capture:
        return parse_pcap(capture.read())
