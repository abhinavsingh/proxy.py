# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any


class Assertions:

    def assertTrue(self, obj: Any) -> None:
        assert obj

    def assertFalse(self, obj: Any) -> None:
        assert not obj

    def assertEqual(self, obj1: Any, obj2: Any) -> None:
        assert obj1 == obj2

    def assertNotEqual(self, obj1: Any, obj2: Any) -> None:
        assert obj1 != obj2
