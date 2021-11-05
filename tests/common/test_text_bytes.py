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

from proxy.common.utils import bytes_, text_


class TestTextBytes(unittest.TestCase):

    def test_text(self) -> None:
        self.assertEqual(text_(b'hello'), 'hello')

    def test_text_int(self) -> None:
        self.assertEqual(text_(1), '1')

    def test_text_nochange(self) -> None:
        self.assertEqual(text_('hello'), 'hello')

    def test_bytes(self) -> None:
        self.assertEqual(bytes_('hello'), b'hello')

    def test_bytes_int(self) -> None:
        self.assertEqual(bytes_(1), b'1')

    def test_bytes_nochange(self) -> None:
        self.assertEqual(bytes_(b'hello'), b'hello')
