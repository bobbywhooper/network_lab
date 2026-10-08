import socket
from urllib.parse import urlparse, urljoin


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

    return (
        version.decode("utf-8"),
        int(status_code),
        reason_phrase.decode("utf-8"),
    )


def parse_headers(header):
    headers = {}

    for line in header.split(b"\r\n")[1:]:
        name, value = line.split(b":", 1)

        # HTTP header names are case-insensitive.
        name = name.decode("utf-8").lower()
        value = value.decode("utf-8").strip()

        headers[name] = value

    return headers


def receive_content_length(s, body, content_length):
    while len(body) < content_length:
        remaining = content_length - len(body)
        more_data = s.recv(remaining)

        if more_data == b"":
            raise ConnectionError(
                "Connection closed before complete body was received"
            )

        body += more_data

    return body


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

        # Ignore optional chunk extensions.
        size_bytes = size_bytes.split(b";", 1)[0]
        chunk_size = int(size_bytes, 16)

        if chunk_size == 0:
            break

        # Need chunk bytes + trailing CRLF.
        while len(data) < chunk_size + 2:
            more_data = s.recv(1024)

            if more_data == b"":
                raise ConnectionError(
                    "Connection closed before complete chunk was received"
                )

            data += more_data

        complete_body.extend(data[:chunk_size])

        # Remove chunk data and its trailing CRLF.
        body = data[chunk_size + 2:]

    return bytes(complete_body)


def http_get(host, port=80, path="/"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((host, port))

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        s.sendall(request.encode("utf-8"))

        header, body = receive_headers(s)

        version, status_code, reason_phrase = parse_status_line(header)
        headers = parse_headers(header)

        transfer_encoding = headers.get("transfer-encoding", "").lower()

        if "chunked" in transfer_encoding:
            complete_body = receive_chunked_body(s, body)

        elif "content-length" in headers:
            content_length = int(headers["content-length"])

            complete_body = receive_content_length(
                s,
                body,
                content_length,
            )

        else:
            # Simplified connection-close framing.
            complete_body = bytearray(body)

            while True:
                data = s.recv(4096)

                if data == b"":
                    break

                complete_body.extend(data)

            complete_body = bytes(complete_body)

    return {
        "version": version,
        "status_code": status_code,
        "reason_phrase": reason_phrase,
        "headers": headers,
        "body": complete_body,
    }


def parse_url(url):
    parsed = urlparse(url)

    if parsed.scheme and parsed.scheme != "http":
        raise ValueError(
            f"Unsupported scheme: {parsed.scheme}"
        )

    host = parsed.hostname

    if host is None:
        raise ValueError("URL does not contain a hostname")

    port = parsed.port if parsed.port is not None else 80
    path = parsed.path or "/"

    if parsed.query:
        target = path + "?" + parsed.query
    else:
        target = path

    return {
        "scheme": parsed.scheme,
        "host": host,
        "port": port,
        "target": target,
    }


def fetch(url, max_redirects=5):
    redirects = 0
    current_url = url

    while True:
        parsed = parse_url(current_url)

        response = http_get(
            host=parsed["host"],
            port=parsed["port"],
            path=parsed["target"],
        )

        status = response["status_code"]
        location = response["headers"].get("location")

        if not (300 <= status < 400 and location):
            return response

        if redirects >= max_redirects:
            raise RuntimeError("Maximum redirect limit reached")

        # Handles absolute and relative redirects.
        current_url = urljoin(current_url, location)
        redirects += 1


if __name__ == "__main__":
    response = fetch("http://example.com/")

    print(
        response["version"],
        response["status_code"],
        response["reason_phrase"],
    )

    print("\nHeaders:")
    for name, value in response["headers"].items():
        print(f"{name}: {value}")

    print("\nBody:")
    print(response["body"].decode("utf-8", errors="replace"))
    