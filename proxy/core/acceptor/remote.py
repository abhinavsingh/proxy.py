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
import logging

from typing import Optional, Any

from multiprocessing import connection
from multiprocessing.reduction import recv_handle

from .threadless import Threadless

logger = logging.getLogger(__name__)


class RemoteExecutor(Threadless[connection.Connection]):
    """RemoteExecutor receives work over a Connection object.
    RemoteExecutor uses ``recv_handle`` to accept incoming work.
    """

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
        # Acceptor will not send address for
        # unix socket domain environments.
        addr = None
        if not self.flags.unix_socket_path:
            addr = self.work_queue.recv()
        fileno = recv_handle(self.work_queue)
        self.work_on_tcp_conn(fileno=fileno, addr=addr)
        return False
