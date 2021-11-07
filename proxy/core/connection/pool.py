# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
import multiprocessing

from typing import Set, List, Dict, Tuple

from .server import TcpServerConnection

logger = logging.getLogger(__name__)

# Lock used by ConnectionPool to remain multi-process & multi-thread safe
#
# TODO: Make me lock free
LOCK = multiprocessing.Lock()


class ConnectionPool:
    """Manages connection pool to upstream servers.

    `ConnectionPool` avoids need to reconnect with the upstream
    servers repeatedly when a reusable connection is available
    in the pool.

    A separate pool is maintained for each upstream server.
    So internally, it's a pool of pools.

    TODO: Listen for read events from the connections
    to remove them from the pool when peer closes the
    connection.
    """

    def __init__(self) -> None:
        # Pools of connection per upstream server
        self.pools: Dict[Tuple[str, int], Set[TcpServerConnection]] = {}

    def acquire(self, host: str, port: int) -> TcpServerConnection:
        """Returns a connection for use with the server."""
        with LOCK:
            addr = (host, port)
            # Return a reusable connection if available
            if addr in self.pools:
                for old_conn in self.pools[addr]:
                    if old_conn.is_reusable():
                        old_conn.mark_inuse()
                        logger.debug(
                            'Reusing connection#{2} for upstream {0}:{1}'.format(
                                host, port, id(old_conn),
                            ),
                        )
                        return old_conn
            # Create new connection
            new_conn = TcpServerConnection(*addr)
            if addr not in self.pools:
                self.pools[addr] = set()
            self.pools[addr].add(new_conn)
            logger.debug(
                'Created new connection#{2} for upstream {0}:{1}'.format(
                    host, port, id(new_conn),
                ),
            )
            return new_conn

    def release(self, conn: TcpServerConnection) -> None:
        """Release the connection.

        If the connection has not been closed,
        then it will be retained in the pool for reusability.
        """
        with LOCK:
            if conn.closed:
                logger.debug(
                    'Removing connection#{2} from pool from upstream {0}:{1}'.format(
                        conn.addr[0], conn.addr[1], id(conn),
                    ),
                )
                self.pools[conn.addr].remove(conn)
            else:
                logger.debug(
                    'Retaining connection#{2} to upstream {0}:{1}'.format(
                        conn.addr[0], conn.addr[1], id(conn),
                    ),
                )
                assert not conn.is_reusable()
                # Reset for reusability
                conn.reset()
