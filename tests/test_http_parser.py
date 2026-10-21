import unittest
from unittest.mock import patch

from http_parser import (
    http_get,
    parse_headers,
    parse_status_line,
    parse_url,
    receive_chunked_body,
    receive_content_length,
)


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, amount):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        return chunk[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent = data


class HttpParserTests(unittest.TestCase):
    def test_rejects_response_with_both_transfer_encoding_and_content_length(self):
        wire = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: 4\r\n\r\n"
        )
        with patch("http_parser.socket.create_connection", return_value=FakeSocket([wire])):
            with self.assertRaisesRegex(ValueError, "both Transfer-Encoding and Content-Length"):
                http_get("example.com")

    def test_rejects_unsupported_transfer_encoding_chain(self):
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        with patch("http_parser.socket.create_connection", return_value=FakeSocket([wire])):
            with self.assertRaisesRegex(ValueError, "Only the chunked"):
                http_get("example.com")

    def test_parse_status_line(self):
        self.assertEqual(
            parse_status_line(b"HTTP/1.1 200 OK\r\nContent-Length: 0"),
            ("HTTP/1.1", 200, "OK"),
        )

    def test_rejects_malformed_status_line(self):
        with self.assertRaises(ValueError):
            parse_status_line(b"not an HTTP response")

    def test_headers_are_case_insensitive(self):
        headers = parse_headers(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test: one\r\nX-Test: two"
        )
        self.assertEqual(headers["content-type"], "text/plain")
        self.assertEqual(headers["x-test"], "one, two")

    def test_rejects_malformed_header(self):
        with self.assertRaises(ValueError):
            parse_headers(b"HTTP/1.1 200 OK\r\nMissingColon")

    def test_rejects_invalid_header_name(self):
        with self.assertRaises(ValueError):
            parse_headers(b"HTTP/1.1 200 OK\r\nBad Name: value")

    def test_parse_url_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_url("http://example.com:99999/")

    def test_parse_url_preserves_query(self):
        self.assertEqual(
            parse_url("http://example.com/path?q=hello")["target"],
            "/path?q=hello",
        )

    def test_rejects_https_url(self):
        with self.assertRaises(ValueError):
            parse_url("https://example.com/")

    def test_content_length_reads_only_expected_bytes(self):
        sock = FakeSocket([b"def"])
        self.assertEqual(receive_content_length(sock, b"abc", 6), b"abcdef")

    def test_content_length_rejects_non_integer_length(self):
        for length in (1.5, True, "2"):
            with self.subTest(length=length), self.assertRaises(ValueError):
                receive_content_length(FakeSocket([]), b"", length)

    def test_content_length_detects_truncation(self):
        with self.assertRaises(ConnectionError):
            receive_content_length(FakeSocket([]), b"a", 2)

    def test_decodes_chunked_body(self):
        wire = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
        self.assertEqual(receive_chunked_body(FakeSocket([wire]), b""), b"Wikipedia")

    def test_rejects_invalid_chunk_size(self):
        with self.assertRaises(ValueError):
            receive_chunked_body(FakeSocket([b"Z\r\n"]), b"")


if __name__ == "__main__":
    unittest.main()
