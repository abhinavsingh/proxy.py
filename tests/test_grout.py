# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import sys

import pytest
import unittest

from proxy import grout
from proxy.common.constants import IS_WINDOWS


@pytest.mark.skipif(
    IS_WINDOWS,
    reason="sys.argv replacement don't really work on windows",
)
class TestGrout(unittest.TestCase):

    def test_grout(self) -> None:
        with self.assertRaises(SystemExit):
            original = sys.argv
            sys.argv = ['grout', '-h']
            grout()
            sys.argv = original
