# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       tcp
"""
import socket
import logging
import selectors
from abc import abstractmethod
from typing import Any, TypeVar, Optional

from ...core.work import Work
from ...common.flag import flags
from ...common.types import (
    Readables, Writables, TcpOrTlsSocket, SelectableEvents,
)
from ...common.utils import wrap_socket
from ...core.connection import TcpClientConnection
from ...common.constants import (
    DEFAULT_TIMEOUT, DEFAULT_KEY_FILE, DEFAULT_CERT_FILE,
    DEFAULT_MAX_SEND_SIZE, DEFAULT_CLIENT_RECVBUF_SIZE,
    DEFAULT_SERVER_RECVBUF_SIZE,
)


logger = logging.getLogger(__name__)


flags.add_argument(
    '--key-file',
    type=str,
    default=DEFAULT_KEY_FILE,
    help='Default: None. Server key file to enable end-to-end TLS encryption with clients. '
    'If used, must also pass --cert-file.',
)

flags.add_argument(
    '--cert-file',
    type=str,
    default=DEFAULT_CERT_FILE,
    help='Default: None. Server certificate to enable end-to-end TLS encryption with clients. '
    'If used, must also pass --key-file.',
)

flags.add_argument(
    '--client-recvbuf-size',
    type=int,
    default=DEFAULT_CLIENT_RECVBUF_SIZE,
    help='Default: ' + str(int(DEFAULT_CLIENT_RECVBUF_SIZE / 1024)) +
    ' KB. Maximum amount of data received from the '
    'client in a single recv() operation.',
)

flags.add_argument(
    '--server-recvbuf-size',
    type=int,
    default=DEFAULT_SERVER_RECVBUF_SIZE,
    help='Default: ' + str(int(DEFAULT_SERVER_RECVBUF_SIZE / 1024)) +
    ' KB. Maximum amount of data received from the '
    'server in a single recv() operation.',
)

flags.add_argument(
    '--max-sendbuf-size',
    type=int,
    default=DEFAULT_MAX_SEND_SIZE,
    help='Default: ' + str(int(DEFAULT_MAX_SEND_SIZE / 1024)) +
    ' KB. Maximum amount of data to dispatch in a single send() operation.',
)

flags.add_argument(
    '--timeout',
    type=int,
    default=DEFAULT_TIMEOUT,
    help='Default: ' + str(DEFAULT_TIMEOUT) +
    '.  Number of seconds after which '
    'an inactive connection must be dropped.  Inactivity is defined by no '
    'data sent or received by the client.',
)


T = TypeVar('T', bound=TcpClientConnection)


class BaseTcpServerHandler(Work[T]):
    """BaseTcpServerHandler implements Work interface.

    BaseTcpServerHandler lifecycle is controlled by Threadless core
    using asyncio.  If you want to also support threaded mode, also
    implement the optional run() method from Work class.

    An instance of BaseTcpServerHandler is created for each client
    connection.  BaseTcpServerHandler ensures that server is always
    ready to accept new data from the client.  It also ensures, client
    is ready to accept new data before flushing data to it.

    Most importantly, BaseTcpServerHandler ensures that pending buffers
    to the client are flushed before connection is closed.

    Implementations must provide::

       a. handle_data(data: memoryview) implementation
       b. Optionally, also implement other Work method
          e.g. initialize, is_inactive, shutdown
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.must_flush_before_shutdown = False
        logger.debug(
            'Work#%d accepted from %s',
            self.work.connection.fileno(),
            self.work.address,
        )

    def initialize(self) -> None:
        """Optionally upgrades connection to HTTPS,
        sets ``conn`` in non-blocking mode and initializes
        HTTP protocol plugins."""
        conn = self._optionally_wrap_socket(self.work.connection)
        conn.setblocking(False)
        logger.debug('Handling connection %s' % self.work.address)

    @abstractmethod
    def handle_data(self, data: memoryview) -> Optional[bool]:
        """Optionally return True to close client connection."""
        pass    # pragma: no cover

    async def get_events(self) -> SelectableEvents:
        events = {}
        # We always want to read from client
        # Register for EVENT_READ events
        if self.must_flush_before_shutdown is False:
            events[self.work.connection.fileno()] = selectors.EVENT_READ
        # If there is pending buffer for client
        # also register for EVENT_WRITE events
        if self.work.has_buffer():
            if self.work.connection.fileno() in events:
                events[self.work.connection.fileno()] |= selectors.EVENT_WRITE
            else:
                events[self.work.connection.fileno()] = selectors.EVENT_WRITE
        return events

    async def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        """Return True to shutdown work."""
        teardown = await self.handle_writables(
            writables,
        ) or await self.handle_readables(readables)
        if teardown:
            logger.debug(
                'Shutting down client {0} connection'.format(
                    self.work.address,
                ),
            )
        return teardown

    async def handle_writables(self, writables: Writables) -> bool:
        teardown = False
        if self.work.connection.fileno() in writables and self.work.has_buffer():
            logger.debug(
                'Flushing buffer to client {0}'.format(self.work.address),
            )
            self.work.flush(self.flags.max_sendbuf_size)
            if self.must_flush_before_shutdown is True and \
                    not self.work.has_buffer():
                teardown = True
                self.must_flush_before_shutdown = False
        return teardown

    async def handle_readables(self, readables: Readables) -> bool:
        teardown = False
        if self.work.connection.fileno() in readables:
            try:
                data = self.work.recv(self.flags.client_recvbuf_size)
            except TimeoutError:
                logger.info('Client recv timeout error')
                return True
            if data is None:
                logger.debug(
                    'Connection closed by client {0}'.format(
                        self.work.address,
                    ),
                )
                teardown = True
            else:
                r = self.handle_data(data)
                if isinstance(r, bool) and r is True:
                    logger.debug(
                        'Implementation signaled shutdown for client {0}'.format(
                            self.work.address,
                        ),
                    )
                    if self.work.has_buffer():
                        logger.debug(
                            'Client {0} has pending buffer, will be flushed before shutting down'.format(
                                self.work.address,
                            ),
                        )
                        self.must_flush_before_shutdown = True
                    else:
                        teardown = True
        return teardown

    def _encryption_enabled(self) -> bool:
        return self.flags.keyfile is not None and \
            self.flags.certfile is not None

    def _optionally_wrap_socket(self, conn: socket.socket) -> TcpOrTlsSocket:
        """Attempts to wrap accepted client connection using provided certificates.

        Shutdown and closes client connection upon error.
        """
        if self._encryption_enabled():
            assert self.flags.keyfile and self.flags.certfile
            # TODO(abhinavsingh): Insecure TLS versions must not be accepted by default
            conn = wrap_socket(conn, self.flags.keyfile, self.flags.certfile)
            self.work._conn = conn
        return conn
