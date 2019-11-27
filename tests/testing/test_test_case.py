# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
import proxy

from proxy.common.utils import get_available_port


class TestTestCase(unittest.TestCase):

    def test_wait_for_server(self) -> None:
        with self.assertRaises(TimeoutError):
            proxy.TestCase.wait_for_server(
                get_available_port(), wait_for_seconds=1)
