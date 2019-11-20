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
import os
import sys
import time
import unittest
import logging

from types import TracebackType
from typing import List, Optional, Generator, Any, Type

from .common.utils import bytes_, get_available_port, new_socket_connection
from .common.flags import Flags
from .core.acceptor import AcceptorPool
from .http.handler import HttpProtocolHandler

logger = logging.getLogger(__name__)


class Proxy:

    def __init__(self, input_args: Optional[List[str]], **opts: Any) -> None:
        self.flags = Flags.initialize(input_args, **opts)
        self.acceptors: Optional[AcceptorPool] = None

    def write_pid_file(self) -> None:
        if self.flags.pid_file is not None:
            with open(self.flags.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))

    def delete_pid_file(self) -> None:
        if self.flags.pid_file and os.path.exists(self.flags.pid_file):
            os.remove(self.flags.pid_file)

    def __enter__(self) -> 'Proxy':
        self.acceptors = AcceptorPool(
            flags=self.flags,
            work_klass=HttpProtocolHandler
        )
        self.acceptors.setup()
        self.write_pid_file()
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType]) -> None:
        assert self.acceptors
        self.acceptors.shutdown()
        self.delete_pid_file()


class TestCase(unittest.TestCase):
    """Base TestCase class that automatically setup and teardown proxy.py."""

    DEFAULT_PROXY_PY_STARTUP_FLAGS = [
        '--num-workers', '1',
        '--threadless',
    ]

    PROXY: Optional[Proxy] = None
    PROXY_PORT: int = 8899
    INPUT_ARGS: Optional[List[str]] = None
    ENABLE_VCR: bool = False

    @classmethod
    def setUpClass(cls) -> None:
        cls.PROXY_PORT = get_available_port()
        cls.INPUT_ARGS = getattr(cls, 'PROXY_PY_STARTUP_FLAGS') \
            if hasattr(cls, 'PROXY_PY_STARTUP_FLAGS') \
            else cls.DEFAULT_PROXY_PY_STARTUP_FLAGS
        cls.INPUT_ARGS.append('--port')
        cls.INPUT_ARGS.append(str(cls.PROXY_PORT))
        cls.PROXY = Proxy(input_args=cls.INPUT_ARGS)
        cls.PROXY.__enter__()
        cls.wait_for_server(cls.PROXY_PORT)

    @staticmethod
    def wait_for_server(proxy_port: int) -> None:
        """Wait for proxy.py server to come up."""
        while True:
            try:
                conn = new_socket_connection(
                    ('localhost', proxy_port))
                conn.close()
                break
            except ConnectionRefusedError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls) -> None:
        assert cls.PROXY
        cls.PROXY.__exit__(None, None, None)
        cls.PROXY = None
        cls.PROXY_PORT = 8899
        cls.INPUT_ARGS = None

    @contextlib.contextmanager
    def vcr(self) -> Generator[None, None, None]:
        self.ENABLE_VCR = True
        try:
            yield
        finally:
            self.ENABLE_VCR = False

    def run(self, result: Optional[unittest.TestResult] = None) -> Any:
        super().run(result)


@contextlib.contextmanager
def start(
        input_args: Optional[List[str]] = None,
        **opts: Any) -> Generator[Proxy, None, None]:
    """Deprecated.  Kept for backward compatibility.

    New users must directly use proxy.Proxy context manager class."""
    try:
        with Proxy(input_args, **opts) as p:
            yield p
    except KeyboardInterrupt:
        pass


def main(
        input_args: Optional[List[str]] = None,
        **opts: Any) -> None:
    try:
        with Proxy(input_args=input_args, **opts):
            # TODO: Introduce cron feature instead of mindless sleep
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


def entry_point() -> None:
    main(input_args=sys.argv[1:])
