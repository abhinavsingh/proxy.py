import unittest
from ..common.utils import get_from_dict


class TestUtils(unittest.TestCase):

    def test_get_from_dict(self):
        test_dict = {"a": {"b": {"c": 1}}}

        self.assertEqual(1, get_from_dict(test_dict, "a", "b", "c"))
        self.assertEqual({"b": {"c": 1}}, get_from_dict(test_dict, "a"))

        self.assertIsNone(get_from_dict(test_dict, "b", "c", "a"))
        self.assertIsNone(get_from_dict(None, "a"))
        self.assertIsNone(get_from_dict(555, "a"))
        self.assertIsNone(get_from_dict({}, "a"))
