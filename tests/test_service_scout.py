import unittest

from service_scout import parse_ports, scan_ports


class ParsePortsTests(unittest.TestCase):
    def test_parses_mixed_ports_and_ranges(self):
        self.assertEqual(parse_ports("80,22,8000-8002,22"), [22, 80, 8000, 8001, 8002])

    def test_rejects_empty_specification(self):
        for value in ("", "  ", "80,,443"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_rejects_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-80")

    def test_rejects_malformed_range(self):
        for value in ("abc", "80-abc", "1-2-3"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_rejects_non_string_specification(self):
        with self.assertRaises(ValueError):
            parse_ports(80)

    def test_rejects_out_of_range_ports(self):
        for value in ("0", "65536", "1-65536"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)
 
class ScanPortsValidationTests(unittest.TestCase):
    def test_rejects_invalid_worker_and_timeout_values(self):
        for workers in (0, -1, 1.5, True):
            with self.subTest(workers=workers), self.assertRaises(ValueError):
                scan_ports("127.0.0.1", [], workers=workers)
        for timeout in (0, -1, "1", True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                scan_ports("127.0.0.1", [], timeout=timeout)

    def test_rejects_invalid_port_values_before_scanning(self):
        for ports in ([0], [65536], [80.5], [True], "80"):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                scan_ports("127.0.0.1", ports)


if __name__ == "__main__":
    unittest.main()
