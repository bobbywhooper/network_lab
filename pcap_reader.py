"""Read classic PCAP files and extract basic Ethernet IP TCP/UDP metadata.

This standard-library reader supports IPv4 and basic IPv6 packets. It does not
reassemble IP fragments, parse IPv6 extension headers, or reassemble TCP streams.
"""

import ipaddress
import io
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
IPV6_ETHERTYPE = 0x86DD
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}



def _parse_ethernet_ipv6(packet, offset, timestamp):
    """Parse IPv6 packets whose base header directly identifies TCP or UDP."""
    if len(packet) < offset + 40:
        raise ValueError("Truncated IPv6 header")

    first_word = struct.unpack("!I", packet[offset:offset + 4])[0]
    if first_word >> 28 != 6:
        raise ValueError("Invalid IPv6 header")

    payload_length, next_header = struct.unpack("!H B", packet[offset + 4:offset + 7])
    payload_start = offset + 40
    payload_end = payload_start + payload_length
    if len(packet) < payload_end:
        raise ValueError("Truncated IPv6 payload")

    # Walk common IPv6 extension headers without interpreting their bytes as ports.
    # Fragmented packets are skipped because this reader does not reassemble fragments.
    extension_count = 0
    while next_header in (0, 43, 60, 51, 44):
        extension_count += 1
        if extension_count > 8:
            raise ValueError("IPv6 extension-header chain is too long")
        if next_header == 44:
            return None
        if payload_start + 2 > payload_end:
            raise ValueError("Truncated IPv6 extension header")
        following_header = packet[payload_start]
        if next_header == 51:  # Authentication Header length uses 32-bit words.
            extension_length = (packet[payload_start + 1] + 2) * 4
        else:  # Hop-by-Hop, Routing, and Destination Options use 8-byte units.
            extension_length = (packet[payload_start + 1] + 1) * 8
        if extension_length < 8 or payload_start + extension_length > payload_end:
            raise ValueError("Invalid or truncated IPv6 extension header")
        payload_start += extension_length
        next_header = following_header

    if next_header not in (6, 17):
        return None

    src_ip = str(ipaddress.IPv6Address(packet[offset + 8:offset + 24]))
    dst_ip = str(ipaddress.IPv6Address(packet[offset + 24:offset + 40]))

    if next_header == 6:
        if payload_end - payload_start < 20:
            raise ValueError("Truncated TCP header")
        src_port, dst_port = struct.unpack("!HH", packet[payload_start:payload_start + 4])
        tcp_header_length = (packet[payload_start + 12] >> 4) * 4
        if tcp_header_length < 20 or payload_start + tcp_header_length > payload_end:
            raise ValueError("Invalid or truncated TCP options")
        tcp_flags = packet[payload_start + 13]
        payload_start += tcp_header_length
        transport = "TCP"
    else:
        if payload_end - payload_start < 8:
            raise ValueError("Truncated UDP header")
        src_port, dst_port, udp_length = struct.unpack(
            "!HHH", packet[payload_start:payload_start + 6]
        )
        if udp_length < 8 or payload_start + udp_length > payload_end:
            raise ValueError("Invalid or truncated UDP datagram")
        tcp_flags = None
        payload_end = payload_start + udp_length
        payload_start += 8
        transport = "UDP"

    return {
        "time": timestamp,
        "ip_version": 6,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": transport,
        "payload_length": payload_end - payload_start,
        "tcp_flags": tcp_flags,
        "tcp_syn": bool(tcp_flags is not None and tcp_flags & 0x02),
        "tcp_ack": bool(tcp_flags is not None and tcp_flags & 0x10),
        "tcp_rst": bool(tcp_flags is not None and tcp_flags & 0x04),
        "tcp_fin": bool(tcp_flags is not None and tcp_flags & 0x01),
        "payload_hex": packet[payload_start:payload_end].hex(),
        "ip_length": 40 + payload_length,
    }


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

    if ethertype == IPV6_ETHERTYPE:
        return _parse_ethernet_ipv6(packet, offset, timestamp)
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
    more_fragments = bool(fragment_field & 0x2000)
    if fragment_offset or more_fragments:
        # Without reassembly, transport metadata and payload lengths are incomplete.
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
        tcp_flags = packet[transport_start + 13]
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
        tcp_flags = None
        transport = "UDP"
    else:
        return None

    return {
        "time": timestamp,
        "ip_version": 4,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": transport,
        "payload_length": payload_length,
        "tcp_flags": tcp_flags,
        "tcp_syn": bool(tcp_flags is not None and tcp_flags & 0x02),
        "tcp_ack": bool(tcp_flags is not None and tcp_flags & 0x10),
        "tcp_rst": bool(tcp_flags is not None and tcp_flags & 0x04),
        "tcp_fin": bool(tcp_flags is not None and tcp_flags & 0x01),
        "payload_hex": packet[
            transport_start + (tcp_header_length if transport == "TCP" else 8):
            ip_payload_end if transport == "TCP" else transport_start + udp_length
        ].hex(),
        "ip_length": total_length,
    }


def _parse_pcapng_stream(capture):
    """Parse basic PCAPNG Section Header, Interface, and Enhanced Packet blocks."""
    first = capture.read(12)
    if len(first) < 12 or first[:4] != b"\\x0a\\x0d\\x0d\\x0a":
        raise ValueError("Invalid PCAPNG section header")

    byte_order_magic = first[8:12]
    if byte_order_magic == b"\\x4d\\x3c\\x2b\\x1a":
        byte_order = "<"
    elif byte_order_magic == b"\\x1a\\x2b\\x3c\\x4d":
        byte_order = ">"
    else:
        raise ValueError("Invalid PCAPNG byte-order magic")

    block_length = struct.unpack(byte_order + "I", first[4:8])[0]
    if block_length < 28 or block_length % 4:
        raise ValueError("Invalid PCAPNG section header length")
    remainder = capture.read(block_length - len(first))
    if len(remainder) != block_length - len(first):
        raise ValueError("Truncated PCAPNG section header")
    if struct.unpack(byte_order + "I", remainder[-4:])[0] != block_length:
        raise ValueError("PCAPNG block lengths do not match")

    interfaces = []
    events = []
    timestamp = 0.0

    while True:
        prefix = capture.read(8)
        if not prefix:
            break
        if len(prefix) != 8:
            raise ValueError("Truncated PCAPNG block header")
        block_type, block_length = struct.unpack(byte_order + "II", prefix)
        if block_length < 12 or block_length % 4:
            raise ValueError("Invalid PCAPNG block length")
        body_length = block_length - 12
        body_and_trailer = capture.read(body_length + 4)
        if len(body_and_trailer) != body_length + 4:
            raise ValueError("Truncated PCAPNG block")
        if struct.unpack(byte_order + "I", body_and_trailer[-4:])[0] != block_length:
            raise ValueError("PCAPNG block lengths do not match")
        body = body_and_trailer[:-4]

        if block_type == 0x0A0D0D0A:
            # New section: read its byte-order magic from the block body.
            if len(body) < 16:
                raise ValueError("Truncated PCAPNG section header")
            bom = body[4:8]
            if bom == b"\\x4d\\x3c\\x2b\\x1a":
                byte_order = "<"
            elif bom == b"\\x1a\\x2b\\x3c\\x4d":
                byte_order = ">"
            else:
                raise ValueError("Invalid PCAPNG byte-order magic")
            interfaces = []
        elif block_type == 1:  # Interface Description Block
            if len(body) < 8:
                raise ValueError("Truncated PCAPNG interface block")
            link_type = struct.unpack(byte_order + "H", body[:2])[0]
            snaplen = struct.unpack(byte_order + "I", body[4:8])[0]
            timestamp_resolution = 1_000_000
            option_offset = 8
            while option_offset + 4 <= len(body):
                code, length = struct.unpack(byte_order + "HH", body[option_offset:option_offset + 4])
                option_offset += 4
                if code == 0:
                    break
                if option_offset + length > len(body):
                    raise ValueError("Invalid PCAPNG interface option")
                value = body[option_offset:option_offset + length]
                if code == 9 and length == 1:  # if_tsresol
                    resolution = value[0]
                    if resolution & 0x80:
                        timestamp_resolution = 2 ** (resolution & 0x7F)
                    else:
                        timestamp_resolution = 10 ** resolution
                option_offset += (length + 3) & ~3
            interfaces.append((link_type, snaplen, timestamp_resolution))
        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                raise ValueError("Truncated PCAPNG enhanced packet block")
            interface_id, ts_high, ts_low, captured_length, original_length = struct.unpack(
                byte_order + "IIIII", body[:20]
            )
            if interface_id >= len(interfaces):
                raise ValueError("PCAPNG packet references an unknown interface")
            link_type, snaplen, timestamp_resolution = interfaces[interface_id]
            if captured_length > snaplen or captured_length > MAX_CAPTURED_PACKET_SIZE:
                raise ValueError("PCAPNG packet exceeds configured size limit")
            if original_length < captured_length:
                raise ValueError("PCAPNG original length is smaller than captured length")
            padded_length = (captured_length + 3) & ~3
            if 20 + padded_length > len(body):
                raise ValueError("Truncated PCAPNG packet data")
            if link_type == ETHERNET:
                raw_timestamp = (ts_high << 32) | ts_low
                timestamp = raw_timestamp / timestamp_resolution
                event = _parse_ethernet_ipv4(body[20:20 + captured_length], timestamp)
                if event is not None:
                    events.append(event)
        # Unknown block types are safely ignored after structural validation.

    return events


def _parse_pcap_stream(capture):
    """Read one packet at a time so capture bytes are not all held in memory."""
    start = capture.read(4)
    if start == b"\\x0a\\x0d\\x0d\\x0a":
        capture.seek(0)
        return _parse_pcapng_stream(capture)
    global_header = start + capture.read(GLOBAL_HEADER_SIZE - len(start))
    if len(global_header) < GLOBAL_HEADER_SIZE:
        raise ValueError("PCAP file is shorter than its 24-byte global header")

    magic = global_header[:4]
    if magic not in PCAP_MAGICS:
        raise ValueError("Unsupported PCAP magic or file format")
    byte_order, timestamp_resolution = PCAP_MAGICS[magic]

    major, minor, _timezone, _sigfigs, snaplen, network = struct.unpack(
        byte_order + "HHIIII", global_header[4:]
    )
    if (major, minor) != (2, 4):
        raise ValueError(f"Unsupported PCAP version: {major}.{minor}")
    if snaplen == 0 or snaplen > MAX_CAPTURED_PACKET_SIZE:
        raise ValueError("Invalid PCAP snapshot length")
    if network != ETHERNET:
        raise ValueError("Only Ethernet link-layer PCAP files are supported")

    events = []
    while True:
        record_header = capture.read(RECORD_HEADER_SIZE)
        if not record_header:
            break
        if len(record_header) != RECORD_HEADER_SIZE:
            raise ValueError("Truncated PCAP packet record header")

        seconds, fraction, captured_length, original_length = struct.unpack(
            byte_order + "IIII", record_header
        )
        if fraction >= timestamp_resolution:
            raise ValueError("PCAP timestamp fraction is out of range")
        if captured_length > snaplen or captured_length > MAX_CAPTURED_PACKET_SIZE:
            raise ValueError("PCAP captured packet length exceeds configured limits")
        if original_length < captured_length:
            raise ValueError("PCAP original length is smaller than captured length")

        packet = capture.read(captured_length)
        if len(packet) != captured_length:
            raise ValueError("Truncated PCAP packet data")

        timestamp = seconds + fraction / timestamp_resolution
        event = _parse_ethernet_ipv4(packet, timestamp)
        if event is not None:
            events.append(event)

    return events


def parse_pcap(data):
    """Parse classic PCAP bytes into packet metadata dictionaries."""
    return _parse_pcap_stream(io.BytesIO(data))


def read_pcap(filename):
    """Read a classic PCAP file without loading the full capture into memory."""
    with open(filename, "rb") as capture:
        return _parse_pcap_stream(capture)
