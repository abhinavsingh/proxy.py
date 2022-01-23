# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import asyncio
from typing import Any, Optional
from multiprocessing import connection

from .threadless import Threadless


class BaseRemoteExecutor(Threadless[connection.Connection]):
    """A threadless executor implementation which receives work over a connection."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def loop(self) -> Optional[asyncio.AbstractEventLoop]:
        if self._loop is None:
            self._loop = asyncio.get_event_loop_policy().get_event_loop()
        return self._loop

    def work_queue_fileno(self) -> Optional[int]:
        return self.work_queue.fileno()

    def close_work_queue(self) -> None:
        self.work_queue.close()

    def receive_from_work_queue(self) -> bool:
        self.work(self.work_queue.recv())
        return False
