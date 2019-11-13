# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import contextlib
import os
import sys
import time
import unittest
import logging
from typing import List, Optional, Generator, Any

from .common.flags import Flags
from .common.utils import bytes_, get_available_port, new_socket_connection
from .core.acceptor import AcceptorPool
from .http.handler import HttpProtocolHandler

logger = logging.getLogger(__name__)


class TestCase(unittest.TestCase):
    """Base TestCase class that automatically setup and teardown proxy.py."""

    DEFAULT_PROXY_PY_STARTUP_FLAGS = [
        '--num-workers', '1',
    ]

    def run(self, result: Optional[unittest.TestResult] = None) -> Any:
        self.proxy_port = get_available_port()

        flags = getattr(self, 'PROXY_PY_STARTUP_FLAGS') \
            if hasattr(self, 'PROXY_PY_STARTUP_FLAGS') \
            else self.DEFAULT_PROXY_PY_STARTUP_FLAGS
        flags.append('--port')
        flags.append(str(self.proxy_port))

        with start(flags):
            # Wait for proxy.py server to come up
            while True:
                try:
                    conn = new_socket_connection(
                        ('::1', self.proxy_port))
                    break
                except ConnectionRefusedError:
                    time.sleep(0.1)
                finally:
                    conn.close()
            # Run tests
            super().run(result)


@contextlib.contextmanager
def start(
        input_args: Optional[List[str]] = None,
        **opts: Any) -> Generator[None, None, None]:
    flags = Flags.initialize(input_args, **opts)
    try:
        acceptor_pool = AcceptorPool(
            flags=flags,
            work_klass=HttpProtocolHandler
        )

        if flags.pid_file is not None:
            with open(flags.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))

        try:
            acceptor_pool.setup()
            yield
        except Exception as e:
            logger.exception('exception', exc_info=e)
        finally:
            acceptor_pool.shutdown()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        if flags.pid_file and os.path.exists(flags.pid_file):
            os.remove(flags.pid_file)


def main(
        input_args: Optional[List[str]] = None,
        **opts: Any) -> None:
    with start(input_args=input_args, **opts):
        # TODO: Introduce cron feature instead of mindless sleep
        while True:
            time.sleep(1)


def entry_point() -> None:
    main(input_args=sys.argv[1:])
