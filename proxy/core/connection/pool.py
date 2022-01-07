# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       reusability
"""
import socket
import logging
import selectors

from typing import TYPE_CHECKING, Set, Dict, Tuple

from ...common.flag import flags
from ...common.types import Readables, SelectableEvents, Writables

from ..acceptor.work import Work

from .server import TcpServerConnection

logger = logging.getLogger(__name__)


flags.add_argument(
    '--enable-conn-pool',
    action='store_true',
    default=False,
    help='Default: False.  (WIP) Enable upstream connection pooling.',
)


class UpstreamConnectionPool(Work[TcpServerConnection]):
    """Manages connection pool to upstream servers.

    `UpstreamConnectionPool` avoids need to reconnect with the upstream
    servers repeatedly when a reusable connection is available
    in the pool.

    A separate pool is maintained for each upstream server.
    So internally, it's a pool of pools.

    Internal data structure maintains references to connection objects
    that pool owns or has borrowed.  Borrowed connections are marked as
    NOT reusable.

    For reusable connections only, pool listens for read events
    to detect broken connections.  This can happen if pool has opened
    a connection, which was never used and eventually reaches
    upstream server timeout limit.

    When a borrowed connection is returned back to the pool,
    the connection is marked as reusable again.  However, if
    returned connection has already been closed, it is removed
    from the internal data structure.

    TODO: Ideally, `UpstreamConnectionPool` must be shared across
    all cores to make SSL session cache to also work
    without additional out-of-bound synchronizations.

    TODO: `UpstreamConnectionPool` currently WON'T work for
    HTTPS connection. This is because of missing support for
    session cache, session ticket, abbr TLS handshake
    and other necessary features to make it work.

    NOTE: However, currently for all HTTP only upstream connections,
    `UpstreamConnectionPool` can be used to remove slow starts.
    """

    def __init__(self) -> None:
        self.connections: Dict[int, TcpServerConnection] = {}
        self.pools: Dict[Tuple[str, int], Set[TcpServerConnection]] = {}

    def add(self, addr: Tuple[str, int]) -> TcpServerConnection:
        """Creates and add a new connection to the pool."""
        new_conn = TcpServerConnection(addr[0], addr[1])
        new_conn.connect()
        self._add(new_conn)
        logger.debug(
            'Created new connection#{2} for upstream {0}:{1}'.format(
                addr[0], addr[1], id(new_conn),
            ),
        )
        return new_conn

    def acquire(self, addr: Tuple[str, int]) -> Tuple[bool, TcpServerConnection]:
        """Returns a reusable connection from the pool.

        If none exists, will create and return a new connection."""
        if addr in self.pools:
            for old_conn in self.pools[addr]:
                if old_conn.is_reusable():
                    old_conn.mark_inuse()
                    logger.debug(
                        'Reusing connection#{2} for upstream {0}:{1}'.format(
                            addr[0], addr[1], id(old_conn),
                        ),
                    )
                    return False, old_conn
        new_conn = self.add(addr)
        new_conn.mark_inuse()
        return True, new_conn

    def release(self, conn: TcpServerConnection) -> None:
        """Release a previously acquired connection.

        If the connection has not been closed,
        then it will be retained in the pool for reusability.
        """
        assert not conn.is_reusable()
        if conn.closed:
            logger.debug(
                'Removing connection#{2} from pool from upstream {0}:{1}'.format(
                    conn.addr[0], conn.addr[1], id(conn),
                ),
            )
            self._remove(conn.connection.fileno())
        else:
            logger.debug(
                'Retaining connection#{2} to upstream {0}:{1}'.format(
                    conn.addr[0], conn.addr[1], id(conn),
                ),
            )
            # Reset for reusability
            conn.reset()

    async def get_events(self) -> SelectableEvents:
        """Returns read event flag for all reusable connections in the pool."""
        events = {}
        for connections in self.pools.values():
            for conn in connections:
                if conn.is_reusable():
                    events[conn.connection.fileno()] = selectors.EVENT_READ
        return events

    async def handle_events(self, readables: Readables, _writables: Writables) -> bool:
        """Removes reusable connection from the pool.

        When pool is the owner of connection, we don't expect a read event from upstream
        server.  A read event means either upstream closed the connection or connection
        has somehow reached an illegal state e.g. upstream sending data for previous
        connection acquisition lifecycle."""
        for fileno in readables:
            if TYPE_CHECKING:
                assert isinstance(fileno, int)
            logger.debug('Upstream fd#{0} is read ready'.format(fileno))
            self._remove(fileno)
        return False

    def _add(self, conn: TcpServerConnection) -> None:
        """Adds a new connection to internal data structure."""
        if conn.addr not in self.pools:
            self.pools[conn.addr] = set()
        conn._reusable = True
        self.pools[conn.addr].add(conn)
        self.connections[conn.connection.fileno()] = conn

    def _remove(self, fileno: int) -> None:
        """Remove a connection by descriptor from the internal data structure."""
        conn = self.connections[fileno]
        logger.debug('Removing conn#{0} from pool'.format(id(conn)))
        conn.connection.shutdown(socket.SHUT_WR)
        conn.close()
        self.pools[conn.addr].remove(conn)
        del self.connections[fileno]
