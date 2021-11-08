# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import socket
import selectors
import ssl
import time
import contextlib
import errno
import logging

from typing import Tuple, List, Union, Optional, Generator, Dict, Any

from .plugin import HttpProtocolHandlerPlugin
from .parser import HttpParser, httpParserStates, httpParserTypes
from .exception import HttpProtocolException

from ..common.types import Readables, Writables
from ..common.utils import wrap_socket
from ..core.base import BaseTcpServerHandler
from ..core.connection import TcpClientConnection
from ..common.flag import flags
from ..common.constants import DEFAULT_CLIENT_RECVBUF_SIZE, DEFAULT_KEY_FILE, DEFAULT_TIMEOUT


logger = logging.getLogger(__name__)


flags.add_argument(
    '--client-recvbuf-size',
    type=int,
    default=DEFAULT_CLIENT_RECVBUF_SIZE,
    help='Default: 1 MB. Maximum amount of data received from the '
    'client in a single recv() operation. Bump this '
    'value for faster uploads at the expense of '
    'increased RAM.',
)
flags.add_argument(
    '--key-file',
    type=str,
    default=DEFAULT_KEY_FILE,
    help='Default: None. Server key file to enable end-to-end TLS encryption with clients. '
    'If used, must also pass --cert-file.',
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

SelectedEventsGeneratorType = Generator[
    Tuple[Readables, Writables],
    None, None,
]


class HttpProtocolHandler(BaseTcpServerHandler):
    """HTTP, HTTPS, HTTP2, WebSockets protocol handler.

    Accepts `Client` connection and delegates to HttpProtocolHandlerPlugin.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.start_time: float = time.time()
        self.last_activity: float = self.start_time
        self.request: HttpParser = HttpParser(httpParserTypes.REQUEST_PARSER)
        self.response: HttpParser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.selector: Optional[selectors.DefaultSelector] = None
        if not self.flags.threadless:
            self.selector = selectors.DefaultSelector()
        self.plugins: Dict[str, HttpProtocolHandlerPlugin] = {}

    ##
    # initialize, is_inactive, shutdown, get_events, handle_events
    # overrides Work class definitions.
    ##

    def initialize(self) -> None:
        """Optionally upgrades connection to HTTPS, set conn in non-blocking mode and initializes plugins."""
        conn = self._optionally_wrap_socket(self.work.connection)
        conn.setblocking(False)
        # Update client connection reference if connection was wrapped
        if self._encryption_enabled():
            self.work = TcpClientConnection(conn=conn, addr=self.work.addr)
        if b'HttpProtocolHandlerPlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'HttpProtocolHandlerPlugin']:
                instance: HttpProtocolHandlerPlugin = klass(
                    self.uid,
                    self.flags,
                    self.work,
                    self.request,
                    self.event_queue,
                )
                self.plugins[instance.name()] = instance
        logger.debug('Handling connection %r' % self.work.connection)

    def is_inactive(self) -> bool:
        if not self.work.has_buffer() and \
                self._connection_inactive_for() > self.flags.timeout:
            return True
        return False

    def shutdown(self) -> None:
        try:
            # Flush pending buffer in threaded mode only.
            # For threadless mode, BaseTcpServerHandler implements
            # the must_flush_before_shutdown logic automagically.
            if self.selector:
                self._flush()

            # Invoke plugin.on_client_connection_close
            for plugin in self.plugins.values():
                plugin.on_client_connection_close()

            logger.debug(
                'Closing client connection %r '
                'at address %s has buffer %s' %
                (self.work.connection, self.work.address, self.work.has_buffer()),
            )

            conn = self.work.connection
            # Unwrap if wrapped before shutdown.
            if self._encryption_enabled() and \
                    isinstance(self.work.connection, ssl.SSLSocket):
                conn = self.work.connection.unwrap()
            conn.shutdown(socket.SHUT_WR)
            logger.debug('Client connection shutdown successful')
        except OSError:
            pass
        finally:
            self.work.connection.close()
            logger.debug('Client connection closed')
            super().shutdown()

    def get_events(self) -> Dict[socket.socket, int]:
        # Get default client events
        events: Dict[socket.socket, int] = super().get_events()
        # HttpProtocolHandlerPlugin.get_descriptors
        for plugin in self.plugins.values():
            plugin_read_desc, plugin_write_desc = plugin.get_descriptors()
            for r in plugin_read_desc:
                if r not in events:
                    events[r] = selectors.EVENT_READ
                else:
                    events[r] |= selectors.EVENT_READ
            for w in plugin_write_desc:
                if w not in events:
                    events[w] = selectors.EVENT_WRITE
                else:
                    events[w] |= selectors.EVENT_WRITE
        return events

    # We override super().handle_events and never call it
    def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        """Returns True if proxy must teardown."""
        # Flush buffer for ready to write sockets
        teardown = self.handle_writables(writables)
        if teardown:
            return True

        # Invoke plugin.write_to_descriptors
        for plugin in self.plugins.values():
            teardown = plugin.write_to_descriptors(writables)
            if teardown:
                return True

        # Read from ready to read sockets
        teardown = self.handle_readables(readables)
        if teardown:
            return True

        # Invoke plugin.read_from_descriptors
        for plugin in self.plugins.values():
            teardown = plugin.read_from_descriptors(readables)
            if teardown:
                return True

        return False

    def handle_data(self, data: memoryview) -> Optional[bool]:
        if data is None:
            logger.debug('Client closed connection, tearing down...')
            self.work.closed = True
            return True

        try:
            # HttpProtocolHandlerPlugin.on_client_data
            # Can raise HttpProtocolException to teardown the connection
            for plugin in self.plugins.values():
                optional_data = plugin.on_client_data(data)
                if optional_data is None:
                    break
                data = optional_data
            # Don't parse incoming data any further after 1st request has completed.
            #
            # This specially does happen for pipeline requests.
            #
            # Plugins can utilize on_client_data for such cases and
            # apply custom logic to handle request data sent after 1st
            # valid request.
            if data and self.request.state != httpParserStates.COMPLETE:
                # Parse http request
                # TODO(abhinavsingh): Remove .tobytes after parser is
                # memoryview compliant
                self.request.parse(data.tobytes())
                if self.request.state == httpParserStates.COMPLETE:
                    # Invoke plugin.on_request_complete
                    for plugin in self.plugins.values():
                        upgraded_sock = plugin.on_request_complete()
                        if isinstance(upgraded_sock, ssl.SSLSocket):
                            logger.debug(
                                'Updated client conn to %s', upgraded_sock,
                            )
                            self.work._conn = upgraded_sock
                            for plugin_ in self.plugins.values():
                                if plugin_ != plugin:
                                    plugin_.client._conn = upgraded_sock
                        elif isinstance(upgraded_sock, bool) and upgraded_sock is True:
                            return True
        except HttpProtocolException as e:
            logger.debug('HttpProtocolException raised')
            response: Optional[memoryview] = e.response(self.request)
            if response:
                self.work.queue(response)
            return True
        return False

    def handle_writables(self, writables: Writables) -> bool:
        if self.work.connection in writables and self.work.has_buffer():
            logger.debug('Client is ready for writes, flushing buffer')
            self.last_activity = time.time()

            # TODO(abhinavsingh): This hook could just reside within server recv block
            # instead of invoking when flushed to client.
            #
            # Invoke plugin.on_response_chunk
            chunk = self.work.buffer
            for plugin in self.plugins.values():
                chunk = plugin.on_response_chunk(chunk)
                if chunk is None:
                    break

            try:
                # Call super() for client flush
                teardown = super().handle_writables(writables)
                if teardown:
                    return True
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for client',
                )
                return True
            except OSError:
                logger.error('OSError when flushing buffer to client')
                return True
        return False

    def handle_readables(self, readables: Readables) -> bool:
        if self.work.connection in readables:
            logger.debug('Client is ready for reads, reading')
            self.last_activity = time.time()
            try:
                teardown = super().handle_readables(readables)
                if teardown:
                    return teardown
            except ssl.SSLWantReadError:    # Try again later
                logger.warning(
                    'SSLWantReadError encountered while reading from client, will retry ...',
                )
                return False
            except socket.error as e:
                if e.errno == errno.ECONNRESET:
                    # Most requests for mobile devices will end up
                    # with client closed connection.  Using `debug`
                    # here to avoid flooding the logs.
                    logger.debug('%r' % e)
                else:
                    logger.exception(
                        'Exception while receiving from %s connection %r with reason %r' %
                        (self.work.tag, self.work.connection, e),
                    )
                return True
        return False

    ##
    # run() is here to maintain backward compatibility for threaded mode
    ##

    def run(self) -> None:
        """run() method is not used when in --threadless mode.

        This is here just to maintain backward compatibility with threaded mode.
        """
        try:
            self.initialize()
            while True:
                # Teardown if client buffer is empty and connection is inactive
                if self.is_inactive():
                    logger.debug(
                        'Client buffer is empty and maximum inactivity has reached '
                        'between client and server connection, tearing down...',
                    )
                    break
                teardown = self._run_once()
                if teardown:
                    break
        except KeyboardInterrupt:  # pragma: no cover
            pass
        except ssl.SSLError as e:
            logger.exception('ssl.SSLError', exc_info=e)
        except Exception as e:
            logger.exception(
                'Exception while handling connection %r' %
                self.work.connection, exc_info=e,
            )
        finally:
            self.shutdown()

    ##
    # Internal methods
    ##

    def _encryption_enabled(self) -> bool:
        return self.flags.keyfile is not None and \
            self.flags.certfile is not None

    def _optionally_wrap_socket(
            self, conn: socket.socket,
    ) -> Union[ssl.SSLSocket, socket.socket]:
        """Attempts to wrap accepted client connection using provided certificates.

        Shutdown and closes client connection upon error.
        """
        if self._encryption_enabled():
            assert self.flags.keyfile and self.flags.certfile
            # TODO(abhinavsingh): Insecure TLS versions must not be accepted by default
            conn = wrap_socket(conn, self.flags.keyfile, self.flags.certfile)
        return conn

    @contextlib.contextmanager
    def _selected_events(self) -> SelectedEventsGeneratorType:
        assert self.selector
        events = self.get_events()
        for fd in events:
            self.selector.register(fd, events[fd])
        ev = self.selector.select(timeout=1)
        readables = []
        writables = []
        for key, mask in ev:
            if mask & selectors.EVENT_READ:
                readables.append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fileobj)
        yield (readables, writables)
        for fd in events:
            self.selector.unregister(fd)

    def _run_once(self) -> bool:
        with self._selected_events() as (readables, writables):
            teardown = self.handle_events(readables, writables)
            if teardown:
                return True
            return False

    def _flush(self) -> None:
        assert self.selector
        if not self.work.has_buffer():
            return
        try:
            self.selector.register(
                self.work.connection,
                selectors.EVENT_WRITE,
            )
            while self.work.has_buffer():
                ev: List[
                    Tuple[selectors.SelectorKey, int]
                ] = self.selector.select(timeout=1)
                if len(ev) == 0:
                    continue
                self.work.flush()
        except BrokenPipeError:
            pass
        finally:
            self.selector.unregister(self.work.connection)

    def _connection_inactive_for(self) -> float:
        return time.time() - self.last_activity
