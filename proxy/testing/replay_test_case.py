# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from .base import BaseTestCase
from ..proxy import Proxy
from ..common.utils import get_available_port
from ..plugin import CacheResponsesPlugin


class ReplayTestCase(BaseTestCase):
    """Base TestCase class that automatically setup and teardown proxy.py."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.PROXY_PORT = get_available_port()

        cls.INPUT_ARGS = getattr(cls, 'PROXY_PY_STARTUP_FLAGS') \
            if hasattr(cls, 'PROXY_PY_STARTUP_FLAGS') \
            else cls.DEFAULT_PROXY_PY_STARTUP_FLAGS
        cls.INPUT_ARGS.append('--hostname')
        cls.INPUT_ARGS.append('0.0.0.0')
        cls.INPUT_ARGS.append('--port')
        cls.INPUT_ARGS.append(str(cls.PROXY_PORT))

        cls.PROXY = Proxy(input_args=cls.INPUT_ARGS)
        cls.PROXY.flags.plugins[b'HttpProxyBasePlugin'].append(
            CacheResponsesPlugin)

        cls.PROXY.__enter__()
        cls.wait_for_server(cls.PROXY_PORT)
