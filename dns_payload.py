"""Small, defensive DNS message metadata parser for captured UDP payloads."""

import struct


def _decode_name(message, offset):
    labels = []
    cursor = offset
    resume_offset = None
    visited = set()

    while True:
        if cursor >= len(message):
            raise ValueError("Truncated DNS name")
        length = message[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message) or pointer in visited:
                raise ValueError("Invalid or cyclic DNS compression pointer")
            visited.add(pointer)
            if resume_offset is None:
                resume_offset = cursor + 2
            cursor = pointer
            continue

        if length & 0xC0:
            raise ValueError("Unsupported DNS label encoding")
        cursor += 1
        if length == 0:
            return ".".join(labels), (resume_offset if resume_offset is not None else cursor)
        if length > 63 or cursor + length > len(message):
            raise ValueError("Invalid or truncated DNS label")
        try:
            labels.append(message[cursor:cursor + length].decode("ascii"))
        except UnicodeDecodeError as error:
            raise ValueError("DNS label is not ASCII") from error
        cursor += length


def parse_dns_payload(payload):
    """Return DNS header/question metadata; raise ValueError for malformed data."""
    if len(payload) < 12:
        raise ValueError("DNS payload is shorter than its header")

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", payload[:12]
    )
    offset = 12
    questions = []

    # Bound the work and avoid accepting impossible question counts.
    if qdcount > (len(payload) - 12) // 5:
        raise ValueError("DNS question count exceeds packet size")

    for _ in range(qdcount):
        name, offset = _decode_name(payload, offset)
        if offset + 4 > len(payload):
            raise ValueError("Truncated DNS question fields")
        qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})

    return {
        "transaction_id": transaction_id,
        "is_response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0x0F,
        "authoritative": bool(flags & 0x0400),
        "truncated": bool(flags & 0x0200),
        "recursion_desired": bool(flags & 0x0100),
        "recursion_available": bool(flags & 0x0080),
        "rcode": flags & 0x000F,
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
        "questions": questions,
    }
