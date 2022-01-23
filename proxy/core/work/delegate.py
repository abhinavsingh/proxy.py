# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import TYPE_CHECKING, Optional
from multiprocessing.reduction import send_handle


if TYPE_CHECKING:   # pragma: no cover
    import socket
    import multiprocessing
    from multiprocessing import connection

    from ...common.types import HostPort


def delegate_work_to_pool(
        worker_pid: int,
        work_queue: 'connection.Connection',
        work_lock: 'multiprocessing.synchronize.Lock',
        conn: 'socket.socket',
        addr: Optional['HostPort'],
        unix_socket_path: Optional[str] = None,
) -> None:
    """Utility method to delegate a work to threadless executor pool."""
    with work_lock:
        # Accepted client address is empty string for
        # unix socket domain, avoid sending empty string
        # for optimization.
        if not unix_socket_path:
            work_queue.send(addr)
        send_handle(
            work_queue,
            conn.fileno(),
            worker_pid,
        )
        conn.close()
