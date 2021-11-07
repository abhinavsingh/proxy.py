# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Set, List, Dict, Tuple

from .server import TcpServerConnection


class ConnectionPool:
    """Manages connection pool to upstream servers.

    `ConnectionPool` avoids need to reconnect with the upstream
    servers repeatedly when a reusable connection is available
    in the pool.

    A separate pool is maintained for each upstream server.
    So internally, it's a pool of pools.
    """

    def __init__(self) -> None:
        # List of all connection objects
        #
        # TODO: Listen for read events from the connections
        # to remove them from the pool when peer closes the
        # connection.
        self.connections: List[TcpServerConnection] = []
        # Pools of connection per upstream server
        # Values are list of indexes into the connections list
        self.pools: Dict[Tuple[str, int], Set[int]] = {}

    def acquire(self, host: str, port: int) -> TcpServerConnection:
        """Returns a connection for use with the server."""
        addr = (host, port)
        # Return a reusable connection if available
        if addr in self.pools:
            indexes = self.pools[addr]
            for index in indexes:
                if self.connections[index].is_reusable():
                    self.connections[index].mark_inuse()
                    return self.connections[index]
        # Create new connection
        conn = TcpServerConnection(*addr)
        self.connections.append(conn)
        if addr not in self.pools:
            self.pools[addr] = set()
        self.pools[addr].add(len(self.connections) - 1)
        return conn

    def release(self, conn: TcpServerConnection) -> None:
        """Release the connection.

        If the connection has not been closed,
        then it will be retained in the pool for reusability.
        """
        if conn.closed:
            # Remove the connection from the pool
            self.pools[conn.addr].remove(self.connections.index(conn))
            self.connections.remove(conn)
        else:
            assert not conn.is_reusable()
            # Reset for reusability
            conn.reset()
