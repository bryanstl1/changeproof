import unittest
from unittest.mock import patch
from changeproof.cli import fetch_json, compare

class HardeningTests(unittest.TestCase):
    def test_rejects_url_control_chars(self):
        with self.assertRaises(ValueError):
            fetch_json('https://example.com/\r\nInjected: yes')
    def test_rejects_nonstandard_port(self):
        with self.assertRaises(ValueError):
            fetch_json('https://example.com:8443/api')
    def test_rejects_credentials(self):
        with self.assertRaises(ValueError):
            fetch_json('https://user:secret@example.com/api')
    def test_rejects_private_ip(self):
        with patch('socket.getaddrinfo', return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):
                fetch_json('https://example.com/api')
    def test_ignores_timestamp(self):
        self.assertEqual(compare({'updated':'a'}, {'updated':'b'}, ignored=['$.updated']), [])
