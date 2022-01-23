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
import contextlib
from typing import Any

from .fd import ThreadlessFdExecutor
from ..local import LocalExecutor
from ....common.backports import NonBlockingQueue


class LocalFdExecutor(LocalExecutor, ThreadlessFdExecutor[NonBlockingQueue]):

    def receive_from_work_queue(self) -> bool:
        with contextlib.suppress(queue.Empty):
            work = self.work_queue.get()
            if isinstance(work, bool) and work is False:
                return True
            self.initialize(work)
        return False

    def initialize(self, work: Any) -> None:
        assert isinstance(work, tuple)
        conn, addr = work
        # NOTE: Here we are assuming to receive a connection object
        # and not a fileno because we are a LocalExecutor.
        fileno = conn.fileno()
        self.work(fileno=fileno, addr=addr, conn=conn)
