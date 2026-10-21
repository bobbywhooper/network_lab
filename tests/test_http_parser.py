import unittest

from http_parser import (
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


class HttpParserTests(unittest.TestCase):
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
