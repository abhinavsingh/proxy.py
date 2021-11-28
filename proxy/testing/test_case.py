# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import contextlib
import time
import unittest
from typing import Optional, List, Generator, Any

from ..proxy import Proxy
from ..common.constants import DEFAULT_TIMEOUT
from ..common.utils import new_socket_connection
from ..plugin import CacheResponsesPlugin


class TestCase(unittest.TestCase):
    """Base TestCase class that automatically setup and tear down proxy.py."""

    DEFAULT_PROXY_PY_STARTUP_FLAGS = [
        '--num-workers', '1',
        '--num-acceptors', '1',
        '--threadless',
    ]

    PROXY: Optional[Proxy] = None
    INPUT_ARGS: Optional[List[str]] = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.INPUT_ARGS = getattr(cls, 'PROXY_PY_STARTUP_FLAGS') \
            if hasattr(cls, 'PROXY_PY_STARTUP_FLAGS') \
            else cls.DEFAULT_PROXY_PY_STARTUP_FLAGS
        cls.INPUT_ARGS.append('--hostname')
        cls.INPUT_ARGS.append('0.0.0.0')
        cls.INPUT_ARGS.append('--port')
        cls.INPUT_ARGS.append('0')

        cls.PROXY = Proxy(cls.INPUT_ARGS)
        cls.PROXY.flags.plugins[b'HttpProxyBasePlugin'].append(
            CacheResponsesPlugin,
        )

        cls.PROXY.__enter__()
        assert cls.PROXY.acceptors
        cls.wait_for_server(cls.PROXY.acceptors.flags.port)

    @staticmethod
    def wait_for_server(
        proxy_port: int,
        wait_for_seconds: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Wait for proxy.py server to come up."""
        start_time = time.time()
        while True:
            try:
                new_socket_connection(
                    ('localhost', proxy_port),
                ).close()
                break
            except ConnectionRefusedError:
                time.sleep(0.1)

            if time.time() - start_time > wait_for_seconds:
                raise TimeoutError(
                    'Timed out while waiting for proxy.py to start...',
                )

    @classmethod
    def tearDownClass(cls) -> None:
        assert cls.PROXY
        cls.PROXY.__exit__(None, None, None)
        cls.PROXY = None
        cls.INPUT_ARGS = None

    @contextlib.contextmanager
    def vcr(self) -> Generator[None, None, None]:
        try:
            CacheResponsesPlugin.ENABLED.set()
            yield
        finally:
            CacheResponsesPlugin.ENABLED.clear()

    def run(self, result: Optional[unittest.TestResult] = None) -> Any:
        super().run(result)
