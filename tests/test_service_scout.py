import unittest

from service_scout import parse_ports


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

    def test_rejects_out_of_range_ports(self):
        for value in ("0", "65536", "1-65536"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)


if __name__ == "__main__":
    unittest.main()
