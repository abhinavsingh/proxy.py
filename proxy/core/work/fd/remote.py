# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional
from multiprocessing import connection
from multiprocessing.reduction import recv_handle

from .fd import ThreadlessFdExecutor
from ..remote import RemoteExecutor


class RemoteFdExecutor(RemoteExecutor, ThreadlessFdExecutor[connection.Connection]):
    def receive_from_work_queue(self) -> bool:
        # Acceptor will not send address for
        # unix socket domain environments.
        addr = None
        if not self.flags.unix_socket_path:
            addr = self.work_queue.recv()
        fileno = recv_handle(self.work_queue)
        self.work(fileno=fileno, addr=addr)
        return False

    def work_queue_fileno(self) -> Optional[int]:
        return self.work_queue.fileno()

    def close_work_queue(self) -> None:
        self.work_queue.close()
