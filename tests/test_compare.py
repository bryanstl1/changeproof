import unittest
from changeproof.cli import compare

class CompareTests(unittest.TestCase):
    def test_removed_field(self):
        self.assertEqual(compare({'a': 1}, {})[0]['kind'], 'removed')
    def test_type_change(self):
        self.assertTrue(compare({'id': 1}, {'id': '1'})[0]['breaking'])
    def test_ignored_timestamp(self):
        self.assertEqual(compare({'timestamp': 1}, {'timestamp': 2}, ignored=['$.timestamp']), [])
    def test_added_field(self):
        self.assertFalse(compare({}, {'a': 1})[0]['breaking'])
    def test_boolean_not_number(self):
        self.assertEqual(compare(True, 1)[0]['kind'], 'type_changed')

if __name__ == '__main__':
    unittest.main()
