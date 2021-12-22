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

from typing import Set, Dict, Tuple

from ...common.flag import flags

from .server import TcpServerConnection

logger = logging.getLogger(__name__)


flags.add_argument(
    '--enable-conn-pool',
    action='store_true',
    default=False,
    help='Default: False.  (WIP) Enable upstream connection pooling.',
)


class ConnectionPool:
    """Manages connection pool to upstream servers.

    `ConnectionPool` avoids need to reconnect with the upstream
    servers repeatedly when a reusable connection is available
    in the pool.

    A separate pool is maintained for each upstream server.
    So internally, it's a pool of pools.

    TODO: Listen for read events from the connections
    to remove them from the pool when peer closes the
    connection.  This can also be achieved lazily by
    the pool users.  Example, if acquired connection
    is stale, reacquire.

    TODO: Ideally, ConnectionPool must be shared across
    all cores to make SSL session cache to also work
    without additional out-of-bound synchronizations.

    TODO: ConnectionPool currently WON'T work for
    HTTPS connection. This is because of missing support for
    session cache, session ticket, abbr TLS handshake
    and other necessary features to make it work.

    NOTE: However, for all HTTP only connections, ConnectionPool
    can be used to save upon connection setup time and
    speed-up performance of requests.
    """

    def __init__(self) -> None:
        # Pools of connection per upstream server
        self.pools: Dict[Tuple[str, int], Set[TcpServerConnection]] = {}

    def acquire(self, host: str, port: int) -> Tuple[bool, TcpServerConnection]:
        """Returns a connection for use with the server."""
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
                    return False, old_conn
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
        return True, new_conn

    def release(self, conn: TcpServerConnection) -> None:
        """Release the connection.

        If the connection has not been closed,
        then it will be retained in the pool for re-usability.
        """
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
            # Reset for re-usability
            conn.reset()
