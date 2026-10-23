import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from changeproof.cli import compare, fetch_json, save_report, main

class V06Tests(unittest.TestCase):
    def test_no_change(self):
        self.assertEqual(compare({'a': [1,2]}, {'a':[1,2]}), [])
    def test_nested_removal(self):
        self.assertTrue(compare({'a':{'b':1}}, {'a':{}})[0]['breaking'])
    def test_bool_vs_int(self):
        self.assertEqual(compare(True, 1)[0]['kind'], 'type_changed')
    def test_ignored_field(self):
        self.assertEqual(compare({'t':1}, {'t':2}, ignored=['$.t']), [])
    def test_html_escaped(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'report.html'
            save_report([{'path':'<script>alert(1)</script>', 'kind':'added', 'breaking':False}],html_path=p)
            content=p.read_text()
            self.assertNotIn('<script>', content)
            self.assertIn('&lt;script&gt;',content)
    def test_reject_localhost(self):
        with self.assertRaises(ValueError):
            with patch('socket.getaddrinfo', return_value=[(2,1,6,'',('127.0.0.1',443))]):
                fetch_json('https://example.org')
    def test_reject_http(self):
        with self.assertRaises(ValueError): fetch_json('http://example.org')
    def test_reject_long_url(self):
        with self.assertRaises(ValueError): fetch_json('https://example.org/' + 'a'*9000)
    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'a.json'; b=Path(d)/'b.json'
            a.write_text('{"x": 1}'); b.write_text('{"x": "1"}')
            self.assertEqual(main(['compare',str(a),str(b)]),1)
            b.write_text('{"x": 1}')
            self.assertEqual(main(['compare',str(a),str(b)]),0)
