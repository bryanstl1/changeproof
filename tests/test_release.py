import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from changeproof.cli import compare, fetch_json, main

class ReleaseTests(unittest.TestCase):
    def test_same_json(self): self.assertEqual(compare({'a':1}, {'a':1}), [])
    def test_removed_breaks(self): self.assertTrue(compare({'a':1}, {})[0]['breaking'])
    def test_added_nonbreaking(self): self.assertFalse(compare({}, {'a':1})[0]['breaking'])
    def test_type_breaks(self): self.assertTrue(compare({'a':1}, {'a':'1'})[0]['breaking'])
    def test_ignore(self): self.assertEqual(compare({'time':1}, {'time':2}, ignored=['$.time']), [])
    def test_array_key_reorder(self):
        a={'items':[{'id':1},{'id':2}]}; b={'items':[{'id':2},{'id':1}]}
        self.assertEqual(compare(a,b,array_key='id'), [])
    def test_http_blocked(self):
        with self.assertRaises(ValueError): fetch_json('http://example.com')
    def test_credentials_blocked(self):
        with self.assertRaises(ValueError): fetch_json('https://user:pass@example.com')
    def test_nonstandard_port_blocked(self):
        with self.assertRaises(ValueError): fetch_json('https://example.com:8443')
    def test_bad_limits(self):
        with self.assertRaises(ValueError): fetch_json('https://example.com',timeout=0)
    def test_compare_cli_reports(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); a=root/'a.json'; b=root/'b.json'; report=root/'report.json'; html=root/'report.html'
            a.write_text('{"id": 1}'); b.write_text('{"id": "1"}')
            self.assertEqual(main(['compare',str(a),str(b),'--json',str(report),'--html',str(html)]),1)
            self.assertEqual(json.loads(report.read_text())['breaking_changes'],1)
            self.assertIn('Potential breaking changes',html.read_text())
    def test_capture_mock(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'snapshot.json'
            with patch('changeproof.cli.fetch_json',return_value={'ok':True}):
                self.assertEqual(main(['capture','https://example.com',str(out)]),0)
            self.assertEqual(json.loads(out.read_text()),{'ok':True})
