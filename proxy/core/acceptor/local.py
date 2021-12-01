# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import queue
import logging
import asyncio
import contextlib

from typing import Optional
from typing import Any

from ...common.backports import NonBlockingQueue    # noqa: W0611, F401   pylint: disable=unused-import

from .threadless import Threadless

logger = logging.getLogger(__name__)


class LocalExecutor(Threadless['NonBlockingQueue']):
    """A threadless executor implementation which uses a queue to receive new work."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def loop(self) -> Optional[asyncio.AbstractEventLoop]:
        if self._loop is None:
            self._loop = asyncio.get_event_loop_policy().new_event_loop()
        return self._loop

    def work_queue_fileno(self) -> Optional[int]:
        return None

    def receive_from_work_queue(self) -> bool:
        with contextlib.suppress(queue.Empty):
            work = self.work_queue.get()
            if isinstance(work, bool) and work is False:
                return True
            assert isinstance(work, tuple)
            conn, addr = work
            # NOTE: Here we are assuming to receive a connection object
            # and not a fileno because we are a LocalExecutor.
            fileno = conn.fileno()
            self.work_on_tcp_conn(fileno=fileno, addr=addr, conn=conn)
        return False
