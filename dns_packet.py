"""Build, send, and parse basic DNS messages using the standard library.

This is an educational DNS client focused on A and AAAA-style record parsing.
It validates packet boundaries and response transaction IDs, but is not a
complete replacement for a production DNS resolver.
"""

import argparse
import ipaddress
import secrets
import socket
import struct


DNS_HEADER_SIZE = 12
TYPE_A = 1
CLASS_IN = 1


def encode_name(domain):
    """Encode a dotted domain name into DNS label format."""
    domain = domain.rstrip(".")
    if not domain:
        raise ValueError("Domain name must not be empty")

    encoded = bytearray()
    total_length = 1  # final zero-length label

    for label in domain.split("."):
        try:
            label_bytes = label.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("Domain labels must be ASCII; encode IDNs as punycode") from error

        if not label_bytes or len(label_bytes) > 63:
            raise ValueError("Each DNS label must contain 1 to 63 bytes")

        total_length += 1 + len(label_bytes)
        if total_length > 255:
            raise ValueError("Encoded DNS name exceeds 255 bytes")

        encoded.append(len(label_bytes))
        encoded.extend(label_bytes.lower())

    encoded.append(0)
    return bytes(encoded)


def build_query(domain, qtype=TYPE_A, transaction_id=None):
    """Build a DNS query packet and return (packet, transaction_id)."""
    if not 0 <= qtype <= 65535:
        raise ValueError("qtype must fit in an unsigned 16-bit field")

    if transaction_id is None:
        transaction_id = secrets.randbelow(65536)
    if not 0 <= transaction_id <= 65535:
        raise ValueError("transaction_id must be between 0 and 65535")

    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack("!HH", qtype, CLASS_IN)
    return header + question, transaction_id


def decode_name(packet, offset):
    """Decode a DNS name, following compression pointers safely.

    Returns (name, offset_after_name_in_original_stream).
    """
    labels = []
    cursor = offset
    next_offset = None
    visited_pointers = set()

    while True:
        if cursor >= len(packet):
            raise ValueError("DNS name extends beyond packet")

        length = packet[cursor]

        if length == 0:
            cursor += 1
            if next_offset is None:
                next_offset = cursor
            break

        # The top two bits 11 indicate a compression pointer.
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")

            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet):
                raise ValueError("DNS compression pointer is outside packet")
            if pointer in visited_pointers:
                raise ValueError("DNS compression pointer loop detected")

            visited_pointers.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue

        if length & 0xC0:
            raise ValueError("Unsupported DNS label encoding")

        cursor += 1
        end = cursor + length
        if end > len(packet):
            raise ValueError("Truncated DNS label")

        try:
            labels.append(packet[cursor:end].decode("ascii"))
        except UnicodeDecodeError as error:
            raise ValueError("DNS label contains non-ASCII bytes") from error
        cursor = end

    return ".".join(labels), next_offset


def parse_response(packet, expected_transaction_id=None):
    """Parse DNS header, questions, and answer records with bounds checks."""
    if len(packet) < DNS_HEADER_SIZE:
        raise ValueError("DNS packet is shorter than its 12-byte header")

    (transaction_id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
        "!HHHHHH", packet[:DNS_HEADER_SIZE]
    )

    if expected_transaction_id is not None and transaction_id != expected_transaction_id:
        raise ValueError("DNS transaction ID does not match the query")
    if not flags & 0x8000:
        raise ValueError("DNS packet is not marked as a response")

    offset = DNS_HEADER_SIZE
    questions = []

    for _ in range(qdcount):
        name, offset = decode_name(packet, offset)
        if offset + 4 > len(packet):
            raise ValueError("Truncated DNS question")
        qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})

    answers = []
    for _ in range(ancount):
        name, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("Truncated DNS resource-record header")

        record_type, record_class, ttl, rdlength = struct.unpack(
            "!HHIH", packet[offset:offset + 10]
        )
        offset += 10
        end = offset + rdlength
        if end > len(packet):
            raise ValueError("Truncated DNS resource-record data")

        rdata = packet[offset:end]
        offset = end
        answer = {
            "name": name,
            "type": record_type,
            "class": record_class,
            "ttl": ttl,
            "data": rdata,
        }

        if record_type == TYPE_A and rdlength == 4:
            answer["value"] = str(ipaddress.IPv4Address(rdata))
        elif record_type == 28 and rdlength == 16:
            answer["value"] = str(ipaddress.IPv6Address(rdata))
        elif record_type == 5:
            cname, _ = decode_name(packet, end - rdlength)
            answer["value"] = cname

        answers.append(answer)

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "is_authoritative": bool(flags & 0x0400),
        "recursion_desired": bool(flags & 0x0100),
        "recursion_available": bool(flags & 0x0080),
        "rcode": flags & 0x000F,
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
        "questions": questions,
        "answers": answers,
    }


def query_dns(domain, server="1.1.1.1", timeout=3, qtype=TYPE_A):
    """Send a DNS query over UDP and parse the matching response."""
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    packet, transaction_id = build_query(domain, qtype=qtype)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        response, address = sock.recvfrom(4096)

    parsed = parse_response(response, expected_transaction_id=transaction_id)
    parsed["server"] = address[0]
    return parsed


def main():
    parser = argparse.ArgumentParser(description="Query and parse a basic DNS response")
    parser.add_argument("domain", nargs="?", default="www.example.com")
    parser.add_argument("--server", default="1.1.1.1", help="DNS server IPv4 address")
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()

    try:
        response = query_dns(args.domain, args.server, args.timeout)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"DNS server: {response['server']}")
    print(f"Transaction ID: 0x{response['transaction_id']:04x}")
    print(f"Response code: {response['rcode']}")
    print("Questions:", response["question_count"])
    print("Answers:", response["answer_count"])

    for answer in response["answers"]:
        value = answer.get("value", answer["data"].hex())
        print(f"{answer['name']} TTL={answer['ttl']} TYPE={answer['type']} DATA={value}")


if __name__ == "__main__":
    main()
