import socket
import struct


# ============================================================
# 1. Build DNS Header
# ============================================================

transaction_id = 0x1234
flags = 0x0100          # Recursion Desired
qdcount = 1             # One question
ancount = 0
nscount = 0
arcount = 0

header = struct.pack(
    "!HHHHHH",
    transaction_id,
    flags,
    qdcount,
    ancount,
    nscount,
    arcount
)


# ============================================================
# 2. Encode Domain Name
# ============================================================

domain = "www.example.com"
encoded_domain = bytearray()

for label in domain.split("."):
    encoded_domain.append(len(label))
    encoded_domain.extend(label.encode("utf-8"))

# DNS name terminator
encoded_domain.append(0)


# ============================================================
# 3. Build DNS Question
# ============================================================

qtype = 1      # A record
qclass = 1     # IN (Internet)

question = bytes(encoded_domain) + struct.pack(
    "!HH",
    qtype,
    qclass
)

packet = header + question


# ============================================================
# 4. Send DNS Query over UDP
# ============================================================

dns_server = "1.1.1.1"

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)

    sock.sendto(packet, (dns_server, 53))

    data, address = sock.recvfrom(512)


print("Received from:", address)
print("Response length:", len(data))
print("Raw DNS:", data.hex())


# ============================================================
# 5. Parse DNS Response Header
# ============================================================

response_header = data[:12]

(
    response_transaction_id,
    response_flags,
    qdcount,
    ancount,
    nscount,
    arcount
) = struct.unpack("!HHHHHH", response_header)


print("\n--- DNS Header ---")
print("Transaction ID:", hex(response_transaction_id))
print("Flags:", hex(response_flags))
print("Questions:", qdcount)
print("Answers:", ancount)
print("Authority:", nscount)
print("Additional:", arcount)


# ============================================================
# 6. Decode Important Flags
# ============================================================

qr = (response_flags >> 15) & 1
rd = (response_flags >> 8) & 1
ra = (response_flags >> 7) & 1

# RCODE occupies the lowest four bits
rcode = response_flags & 0xF


print("\n--- Flags ---")
print("QR:", qr)
print("RD:", rd)
print("RA:", ra)
print("RCODE:", rcode)


# ============================================================
# 7. Skip the Question Section
# ============================================================

# DNS header occupies the first 12 bytes.
offset = 12

# Walk through QNAME.
while True:
    length = data[offset]

    if length == 0:
        offset += 1
        break

    # Skip:
    #   1 byte containing label length
    #   N bytes containing the label itself
    offset += 1 + length


# Skip QTYPE (2 bytes) and QCLASS (2 bytes).
offset += 4


# ============================================================
# 8. Parse Answer Records
# ============================================================

print("\n--- A Records ---")

for _ in range(ancount):

    # For this exercise, the NAME is assumed to be
    # a two-byte DNS compression pointer.
    offset += 2

    (
        record_type,
        record_class,
        ttl,
        rdlength
    ) = struct.unpack(
        "!HHIH",
        data[offset:offset + 10]
    )

    # Move past TYPE, CLASS, TTL, and RDLENGTH.
    offset += 10

    # Extract RDATA.
    rdata = data[offset:offset + rdlength]

    # Move to the next resource record.
    offset += rdlength

    # TYPE 1 = A record.
    if record_type == 1 and rdlength == 4:

        octets = []

        for value in rdata:
            octets.append(str(value))

        ip = ".".join(octets)

        print("IP:", ip)
        print("TTL:", ttl)