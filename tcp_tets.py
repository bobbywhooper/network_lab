import socket
from urllib.parse import urlparse
"""""
# AF_INET is used for IPv4 addresses
# SOCK_STREAM is used for TCP connections AKA a byte stream and a reliable connection
host = input("Enter the host to connect to: ")
start_port = int(input("Enter the starting port number: "))
end_port = int(input("Enter the ending port number: "))

ip_address = socket.gethostbyname(host)
im
print(f"Connecting to {host} ({ip_address}) on ports {start_port} to {end_port}...")

for port in range(start_port, end_port + 1):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Set a timeout for the connection attempt
        result = s.connect_ex((ip_address, port))
        if result == 0:
            print(f"Port {port} is open.")
            print(s.getsockname())  # Print the local socket address
            print(s.getpeername())  # Print the remote socket address
        else:
            print(f"Port {port} is closed.")

import socket


def receive_headers(s):
    buffer = bytearray()

    while b"\r\n\r\n" not in buffer:
        data = s.recv(1024)

        if data == b"":
            raise ConnectionError(
                "Connection closed before HTTP headers were complete"
            )

        buffer.extend(data)

    header, body = buffer.split(b"\r\n\r\n", 1)
    return header, body


def parse_status_line(header):
    status_line = header.split(b"\r\n", 1)[0]

    version, status_code, reason_phrase = status_line.split(b" ", 2)

    version = version.decode("utf-8")
    status_code = int(status_code)
    reason_phrase = reason_phrase.decode("utf-8")

    return version, status_code, reason_phrase


def parse_headers(header):
    headers = {}

    for line in header.split(b"\r\n")[1:]:
        name, value = line.split(b":", 1)

        name = name.decode("utf-8")
        value = value.decode("utf-8").strip()

        headers[name] = value

    return headers


def receive_chunked_body(s, body):
    complete_body = bytearray()

    while True:
        # Make sure we have the complete chunk-size line.
        while b"\r\n" not in body:
            more_data = s.recv(1024)

            if more_data == b"":
                raise ConnectionError(
                    "Connection closed before chunk size was received"
                )

            body += more_data

        size_bytes, data = body.split(b"\r\n", 1)
        chunk_size = int(size_bytes, 16)

        # Zero-sized chunk terminates the chunked body.
        if chunk_size == 0:
            break

        # Need chunk data + its trailing CRLF.
        while len(data) < chunk_size + 2:
            more_data = s.recv(1024)

            if more_data == b"":
                raise ConnectionError(
                    "Connection closed before complete chunk was received"
                )

            data += more_data

        chunk_data = data[:chunk_size]
        complete_body.extend(chunk_data)

        # Preserve anything already received for the next chunk.
        body = data[chunk_size + 2:]

    return complete_body

def receive_content_length(s, body, content_length):
    while len(body) < content_length:
        remaining = content_length - len(body)
        more_data = s.recv(remaining)
        if more_data == b'':
            raise ConnectionError("Unsupported HTTP response body framing")
        
        body += more_data

    return body

def http_get(host, port=80, path="/"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "\r\n"
        )

        s.sendall(request.encode("utf-8"))

        header, body = receive_headers(s)

        version, status_code, reason_phrase = parse_status_line(header)
        headers = parse_headers(header)

        if "Transfer-Encoding" in headers and headers["Transfer-Encoding"] == "chunked":
            complete_body = receive_chunked_body(s, body)

        elif "Content-Length" in headers:
            content_length = int(headers["Content-Length"])
            complete_body = receive_content_length(s, body, content_length)

        else:
            raise ValueError("Missing protocol value for header") 

    return {
        "version": version,
        "status_code": status_code,
        "reason_phrase": reason_phrase,
        "headers": headers,
        "body": complete_body,
    }

def fetch(host, port=80, path="/"):
    response = http_get(host=host, port=port, path=path)
    max_redirects = 5
    redirects = 0
    while (
        300 <= response["status_code"] < 400
        and "Location" in response["headers"]
        and redirects < max_redirects
    ): 
        location = response["headers"]["Location"]
        parsed_url = parse_url(location)

        if parsed_url["scheme"]:
                host = parsed_url["host"]
                port = parsed_url["port"]
                path = parsed_url["target"]
        else:
            path = location

        response = http_get(host=host, port=port, path=path)
        redirects += 1

    if 300 <= response["status_code"] < 400 and "Location" in response["headers"]:
        raise RuntimeError("Maximum redirect limit reached")
    
    return response

def parse_url(url):
    parsed = urlparse(url)

    if parsed.query:
        target = parsed.path + "?" + parsed.query
    else: 
        target = parsed.path

    if not parsed.path:
        target = target + "/"

    if parsed.port is None:
        port = 80
    else:
        port = parsed.port

    result = {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": port,
        "target": target
    }

    return result


    

response = http_get("example.com")

print("HTTP Version:", response["version"])
print("Status Code:", response["status_code"])
print("Reason:", response["reason_phrase"])

print("\nHeaders:")
for name, value in response["headers"].items():
    print(f"{name}: {value}")

print("\nResponse Body:")
print(response["body"].decode("utf-8"))



results = socket.getaddrinfo("example.com", 80)
for family, socktype, protocol, canonname, sockaddr in results:
    if family == socket.AF_INET:
        print(f"IP4: {sockaddr[0]}")

    if family == socket.AF_INET6:
        print(f"IP6: {sockaddr[0]}")

"""

import struct

transaction_id = 0x1234
flags = 0x0100
qdcount = 1
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

encoded_domain = bytearray()
domain = "www.example.com"
for label in domain.split("."):
    encoded_domain.append(len(label))
    encoded_domain.extend(label.encode("utf-8"))
encoded_domain.append(0)
question = bytes(encoded_domain) + struct.pack("!HH", 1, 1)

packet = header + question
