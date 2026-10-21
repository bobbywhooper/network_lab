"""A small educational HTTP/1.x client implemented with TCP sockets.

This intentionally supports only plain HTTP (not HTTPS), and implements a
limited subset of HTTP response framing for learning purposes.
"""

import socket
from urllib.parse import urljoin, urlparse


MAX_HEADER_BYTES = 65536
MAX_BODY_BYTES = 10 * 1024 * 1024


def _recv_more(sock, amount=4096):
    data = sock.recv(amount)
    if not data:
        raise ConnectionError("Connection closed before the response was complete")
    return data


def receive_headers(sock, max_header_bytes=MAX_HEADER_BYTES):
    """Read through CRLF-CRLF and return (header_bytes, already_received_body)."""
    buffer = bytearray()

    while b"\r\n\r\n" not in buffer:
        if len(buffer) >= max_header_bytes:
            raise ValueError("HTTP headers exceed configured size limit")
        data = sock.recv(min(4096, max_header_bytes + 1 - len(buffer)))
        if not data:
            raise ConnectionError("Connection closed before HTTP headers were complete")
        buffer.extend(data)

    header, body = buffer.split(b"\r\n\r\n", 1)
    if len(header) > max_header_bytes:
        raise ValueError("HTTP headers exceed configured size limit")
    return bytes(header), bytes(body)


def parse_status_line(header):
    """Parse and validate the HTTP status line."""
    first_line = header.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)

    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise ValueError("Malformed HTTP status line")

    try:
        version = parts[0].decode("ascii")
        status_code = int(parts[1])
        reason = parts[2].decode("iso-8859-1") if len(parts) == 3 else ""
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("Malformed HTTP status line") from error

    if not 100 <= status_code <= 599:
        raise ValueError("HTTP status code is outside the valid range")

    return version, status_code, reason


def parse_headers(header):
    """Parse headers into a lowercase-name dictionary."""
    lines = header.split(b"\r\n")
    headers = {}

    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            raise ValueError("Obsolete folded HTTP headers are not supported")
        if b":" not in line:
            raise ValueError(f"Malformed HTTP header: {line!r}")

        name, value = line.split(b":", 1)
        try:
            decoded_name = name.decode("ascii").strip().lower()
            decoded_value = value.decode("iso-8859-1").strip()
        except UnicodeDecodeError as error:
            raise ValueError("HTTP header contains invalid bytes") from error

        if not decoded_name or any(
            char not in "!#$%&'*+-.^_`|~" and not char.isalnum()
            for char in decoded_name
        ):
            raise ValueError("HTTP header name contains invalid characters")

        # Preserve repeated headers instead of silently losing all but one.
        if decoded_name in headers:
            headers[decoded_name] += ", " + decoded_value
        else:
            headers[decoded_name] = decoded_value

    return headers


def receive_content_length(sock, body, content_length, max_body_bytes=MAX_BODY_BYTES):
    """Read exactly Content-Length bytes or fail on truncation."""
    if not isinstance(content_length, int) or isinstance(content_length, bool):
        raise ValueError("Content-Length must be an integer")
    if not isinstance(max_body_bytes, int) or isinstance(max_body_bytes, bool) or max_body_bytes < 0:
        raise ValueError("max_body_bytes must be a non-negative integer")
    if content_length < 0:
        raise ValueError("Content-Length cannot be negative")
    if content_length > max_body_bytes:
        raise ValueError("HTTP body exceeds configured size limit")

    result = bytearray(body[:content_length])
    if len(result) > content_length:
        result = result[:content_length]

    while len(result) < content_length:
        result.extend(_recv_more(sock, min(4096, content_length - len(result))))

    return bytes(result)


def receive_chunked_body(sock, body, max_body_bytes=MAX_BODY_BYTES):
    """Decode chunked transfer coding and validate the terminating trailers."""
    if max_body_bytes < 0:
        raise ValueError("max_body_bytes cannot be negative")

    buffer = bytearray(body)
    result = bytearray()

    def read_until(delimiter, description, limit):
        while delimiter not in buffer:
            if len(buffer) > limit:
                raise ValueError(f"HTTP {description} exceeds configured size limit")
            buffer.extend(_recv_more(sock, min(4096, limit + 1 - len(buffer))))
        before, _, after = buffer.partition(delimiter)
        if len(before) > limit:
            raise ValueError(f"HTTP {description} exceeds configured size limit")
        buffer[:] = after
        return bytes(before)

    while True:
        size_line = read_until(b"\r\n", "chunk-size line", 1024)
        size_text = size_line.split(b";", 1)[0].strip()
        if not size_text or any(byte not in b"0123456789abcdefABCDEF" for byte in size_text):
            raise ValueError("Malformed HTTP chunk size")
        chunk_size = int(size_text, 16)

        if chunk_size == 0:
            if buffer.startswith(b"\r\n"):
                del buffer[:2]
                return bytes(result)

            trailer_block = read_until(b"\r\n\r\n", "chunk trailers", MAX_HEADER_BYTES)
            if trailer_block:
                parse_headers(b"HTTP/1.1 200 OK\r\n" + trailer_block)
            return bytes(result)

        if len(result) + chunk_size > max_body_bytes:
            raise ValueError("HTTP body exceeds configured size limit")

        while len(buffer) < chunk_size + 2:
            buffer.extend(_recv_more(sock, min(4096, chunk_size + 2 - len(buffer))))

        if buffer[chunk_size:chunk_size + 2] != b"\r\n":
            raise ValueError("Malformed HTTP chunk terminator")
        result.extend(buffer[:chunk_size])
        del buffer[:chunk_size + 2]


def http_get(host, port=80, path="/", timeout=5):
    """Make a plain HTTP GET request and return a structured response."""
    if not host:
        raise ValueError("Host must not be empty")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("Request path must start with '/' and contain no CR/LF")
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("ascii"))

        raw_header, body = receive_headers(sock)
        version, status_code, reason_phrase = parse_status_line(raw_header)
        headers = parse_headers(raw_header)

        transfer_encoding = headers.get("transfer-encoding", "").lower()
        if "chunked" in transfer_encoding:
            complete_body = receive_chunked_body(sock, body)
        elif "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except ValueError as error:
                raise ValueError("Invalid Content-Length header") from error
            complete_body = receive_content_length(sock, body, content_length)
        else:
            complete_body = bytearray(body)
            if len(complete_body) > MAX_BODY_BYTES:
                raise ValueError("HTTP body exceeds configured size limit")
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                complete_body.extend(data)
                if len(complete_body) > MAX_BODY_BYTES:
                    raise ValueError("HTTP body exceeds configured size limit")
            complete_body = bytes(complete_body)

    return {
        "version": version,
        "status_code": status_code,
        "reason_phrase": reason_phrase,
        "headers": headers,
        "body": complete_body,
    }


def parse_url(url):
    """Parse an HTTP URL into host, port, and request target."""
    parsed = urlparse(url)

    if parsed.scheme.lower() != "http":
        raise ValueError("Only plain http:// URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not supported")
    if parsed.hostname is None:
        raise ValueError("URL does not contain a hostname")

    try:
        port = parsed.port or 80
    except ValueError as error:
        raise ValueError("URL contains an invalid port") from error

    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    if "\r" in target or "\n" in target:
        raise ValueError("URL path cannot contain CR/LF")

    return {"scheme": "http", "host": parsed.hostname, "port": port, "target": target}


def fetch(url, max_redirects=5, timeout=5):
    """Fetch an HTTP URL and follow redirects, rejecting HTTPS redirects."""
    if not isinstance(max_redirects, int) or isinstance(max_redirects, bool) or max_redirects < 0:
        raise ValueError("max_redirects must be a non-negative integer")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive number")

    redirects = 0
    current_url = url

    while True:
        parsed = parse_url(current_url)
        response = http_get(
            host=parsed["host"],
            port=parsed["port"],
            path=parsed["target"],
            timeout=timeout,
        )

        location = response["headers"].get("location")
        if not (300 <= response["status_code"] < 400 and location):
            return response
        if redirects >= max_redirects:
            raise RuntimeError("Maximum redirect limit reached")

        current_url = urljoin(current_url, location)
        # Validate before making the next network request.
        parse_url(current_url)
        redirects += 1


def main():
    response = fetch("http://example.com/")
    print(response["version"], response["status_code"], response["reason_phrase"])
    print("\nHeaders:")
    for name, value in response["headers"].items():
        print(f"{name}: {value}")
    print("\nBody:")
    print(response["body"].decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
