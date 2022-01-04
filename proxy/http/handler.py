# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import ssl
import time
import errno
import socket
import asyncio
import logging
import selectors

from typing import Tuple, List, Type, Union, Optional, Dict, Any

from ..common.flag import flags
from ..common.utils import wrap_socket
from ..core.base import BaseTcpServerHandler
from ..common.types import Readables, Writables
from ..core.connection import TcpClientConnection
from ..common.constants import DEFAULT_CLIENT_RECVBUF_SIZE, DEFAULT_KEY_FILE
from ..common.constants import DEFAULT_SELECTOR_SELECT_TIMEOUT, DEFAULT_TIMEOUT

from .exception import HttpProtocolException
from .plugin import HttpProtocolHandlerPlugin
from .responses import BAD_REQUEST_RESPONSE_PKT
from .parser import HttpParser, httpParserStates, httpParserTypes


logger = logging.getLogger(__name__)


flags.add_argument(
    '--client-recvbuf-size',
    type=int,
    default=DEFAULT_CLIENT_RECVBUF_SIZE,
    help='Default: ' + str(int(DEFAULT_CLIENT_RECVBUF_SIZE / 1024)) +
    ' KB. Maximum amount of data received from the '
    'client in a single recv() operation.',
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


class HttpProtocolHandler(BaseTcpServerHandler):
    """HTTP, HTTPS, HTTP2, WebSockets protocol handler.

    Accepts `Client` connection and delegates to HttpProtocolHandlerPlugin.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.start_time: float = time.time()
        self.last_activity: float = self.start_time
        self.request: HttpParser = HttpParser(
            httpParserTypes.REQUEST_PARSER,
            enable_proxy_protocol=self.flags.enable_proxy_protocol,
        )
        self.selector: Optional[selectors.DefaultSelector] = None
        if not self.flags.threadless:
            self.selector = selectors.DefaultSelector()
        self.plugin: Optional[HttpProtocolHandlerPlugin] = None

    ##
    # initialize, is_inactive, shutdown, get_events, handle_events
    # overrides Work class definitions.
    ##

    def initialize(self) -> None:
        """Optionally upgrades connection to HTTPS,
        sets ``conn`` in non-blocking mode and initializes
        HTTP protocol plugins.
        """
        conn = self._optionally_wrap_socket(self.work.connection)
        conn.setblocking(False)
        # Update client connection reference if connection was wrapped
        if self._encryption_enabled():
            self.work = TcpClientConnection(conn=conn, addr=self.work.addr)
        # self._initialize_plugins()
        logger.debug('Handling connection %s' % self.work.address)

    def is_inactive(self) -> bool:
        if not self.work.has_buffer() and \
                self._connection_inactive_for() > self.flags.timeout:
            return True
        return False

    def shutdown(self) -> None:
        try:
            # Flush pending buffer in threaded mode only.
            #
            # For threadless mode, BaseTcpServerHandler implements
            # the must_flush_before_shutdown logic automagically.
            if self.selector and self.work.has_buffer():
                self._flush()
            # Invoke plugin.on_client_connection_close
            if self.plugin:
                self.plugin.on_client_connection_close()
            logger.debug(
                'Closing client connection %s has buffer %s' %
                (self.work.address, self.work.has_buffer()),
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
            # Section 4.2.2.13 of RFC 1122 tells us that a close() with any pending readable data
            # could lead to an immediate reset being sent.
            #
            #   "A host MAY implement a 'half-duplex' TCP close sequence, so that an application
            #   that has called CLOSE cannot continue to read data from the connection.
            #   If such a host issues a CLOSE call while received data is still pending in TCP,
            #   or if new data is received after CLOSE is called, its TCP SHOULD send a RST to
            #   show that data was lost."
            #
            self.work.connection.close()
            logger.debug('Client connection closed')
            super().shutdown()

    async def get_events(self) -> Dict[int, int]:
        # Get default client events
        events: Dict[int, int] = await super().get_events()
        # HttpProtocolHandlerPlugin.get_descriptors
        if self.plugin:
            plugin_read_desc, plugin_write_desc = await self.plugin.get_descriptors()
            for rfileno in plugin_read_desc:
                if rfileno not in events:
                    events[rfileno] = selectors.EVENT_READ
                else:
                    events[rfileno] |= selectors.EVENT_READ
            for wfileno in plugin_write_desc:
                if wfileno not in events:
                    events[wfileno] = selectors.EVENT_WRITE
                else:
                    events[wfileno] |= selectors.EVENT_WRITE
        return events

    # We override super().handle_events and never call it
    async def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        """Returns True if proxy must tear down."""
        # Flush buffer for ready to write sockets
        teardown = await self.handle_writables(writables)
        if teardown:
            return True
        # Invoke plugin.write_to_descriptors
        if self.plugin:
            teardown = await self.plugin.write_to_descriptors(writables)
            if teardown:
                return True
        # Read from ready to read sockets
        teardown = await self.handle_readables(readables)
        if teardown:
            return True
        # Invoke plugin.read_from_descriptors
        if self.plugin:
            teardown = await self.plugin.read_from_descriptors(readables)
            if teardown:
                return True
        return False

    def handle_data(self, data: memoryview) -> Optional[bool]:
        """Handles incoming data from client."""
        if data is None:
            logger.debug('Client closed connection, tearing down...')
            self.work.closed = True
            return True
        try:
            # Don't parse incoming data any further after 1st request has completed.
            #
            # This specially does happen for pipeline requests.
            #
            # Plugins can utilize on_client_data for such cases and
            # apply custom logic to handle request data sent after 1st
            # valid request.
            if self.request.state != httpParserStates.COMPLETE:
                if self._parse_first_request(data):
                    return True
            else:
                # HttpProtocolHandlerPlugin.on_client_data
                # Can raise HttpProtocolException to tear down the connection
                if self.plugin:
                    data = self.plugin.on_client_data(data) or data
        except HttpProtocolException as e:
            logger.info('HttpProtocolException: %s' % e)
            response: Optional[memoryview] = e.response(self.request)
            if response:
                self.work.queue(response)
            return True
        return False

    async def handle_writables(self, writables: Writables) -> bool:
        if self.work.connection.fileno() in writables and self.work.has_buffer():
            logger.debug('Client is write ready, flushing...')
            self.last_activity = time.time()
            # TODO(abhinavsingh): This hook could just reside within server recv block
            # instead of invoking when flushed to client.
            #
            # Invoke plugin.on_response_chunk
            chunk = self.work.buffer
            if self.plugin:
                chunk = self.plugin.on_response_chunk(chunk)
            try:
                # Call super() for client flush
                teardown = await super().handle_writables(writables)
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

    async def handle_readables(self, readables: Readables) -> bool:
        if self.work.connection.fileno() in readables:
            logger.debug('Client is read ready, receiving...')
            self.last_activity = time.time()
            try:
                teardown = await super().handle_readables(readables)
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
                    logger.warning(
                        'Exception when receiving from %s connection#%d with reason %r' %
                        (self.work.tag, self.work.connection.fileno(), e),
                    )
                return True
        return False

    ##
    # Internal methods
    ##

    def _initialize_plugin(
            self,
            klass: Type['HttpProtocolHandlerPlugin'],
    ) -> HttpProtocolHandlerPlugin:
        """Initializes passed HTTP protocol handler plugin class."""
        return klass(
            self.uid,
            self.flags,
            self.work,
            self.request,
            self.event_queue,
            self.upstream_conn_pool,
        )

    def _discover_plugin_klass(self, protocol: int) -> Optional[Type['HttpProtocolHandlerPlugin']]:
        """Discovers and return matching HTTP handler plugin matching protocol."""
        if b'HttpProtocolHandlerPlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'HttpProtocolHandlerPlugin']:
                k: Type['HttpProtocolHandlerPlugin'] = klass
                if protocol in k.protocols():
                    return k
        return None

    def _parse_first_request(self, data: memoryview) -> bool:
        # Parse http request
        #
        # TODO(abhinavsingh): Remove .tobytes after parser is
        # memoryview compliant
        self.request.parse(data.tobytes())
        if not self.request.is_complete:
            return False
        # Discover which HTTP handler plugin is capable of
        # handling the current incoming request
        klass = self._discover_plugin_klass(
            self.request.http_handler_protocol,
        )
        if klass is None:
            # No matching protocol class found.
            # Return bad request response and
            # close the connection.
            self.work.queue(BAD_REQUEST_RESPONSE_PKT)
            return True
        assert klass is not None
        self.plugin = self._initialize_plugin(klass)
        # Invoke plugin.on_request_complete
        output = self.plugin.on_request_complete()
        if isinstance(output, bool):
            return output
        assert isinstance(output, ssl.SSLSocket)
        logger.debug(
            'Updated client conn to %s', output,
        )
        self.work._conn = output
        return False

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

    def _connection_inactive_for(self) -> float:
        return time.time() - self.last_activity

    ##
    # run() and _run_once() are here to maintain backward compatibility
    # with threaded mode.  These methods are only called when running
    # in threaded mode.
    ##

    def run(self) -> None:
        """run() method is not used when in --threadless mode.

        This is here just to maintain backward compatibility with threaded mode.
        """
        loop = asyncio.new_event_loop()
        try:
            self.initialize()
            while True:
                # Tear down if client buffer is empty and connection is inactive
                if self.is_inactive():
                    logger.debug(
                        'Client buffer is empty and maximum inactivity has reached '
                        'between client and server connection, tearing down...',
                    )
                    break
                if loop.run_until_complete(self._run_once()):
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
            loop.close()

    async def _run_once(self) -> bool:
        events, readables, writables = await self._selected_events()
        try:
            return await self.handle_events(readables, writables)
        finally:
            assert self.selector
            # TODO: Like Threadless we should not unregister
            # work fds repeatedly.
            for fd in events:
                self.selector.unregister(fd)

    # FIXME: Returning events is only necessary because we cannot use async context manager
    # for < Python 3.8.  As a reason, this method is no longer a context manager and caller
    # is responsible for unregistering the descriptors.
    async def _selected_events(self) -> Tuple[Dict[int, int], Readables, Writables]:
        assert self.selector
        events = await self.get_events()
        for fd in events:
            self.selector.register(fd, events[fd])
        ev = self.selector.select(timeout=DEFAULT_SELECTOR_SELECT_TIMEOUT)
        readables = []
        writables = []
        for key, mask in ev:
            if mask & selectors.EVENT_READ:
                readables.append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fileobj)
        return (events, readables, writables)

    def _flush(self) -> None:
        assert self.selector
        logger.debug('Flushing pending data')
        try:
            self.selector.register(
                self.work.connection,
                selectors.EVENT_WRITE,
            )
            while self.work.has_buffer():
                logging.debug('Waiting for client read ready')
                ev: List[
                    Tuple[selectors.SelectorKey, int]
                ] = self.selector.select(timeout=DEFAULT_SELECTOR_SELECT_TIMEOUT)
                if len(ev) == 0:
                    continue
                self.work.flush()
        except BrokenPipeError:
            pass
        finally:
            self.selector.unregister(self.work.connection)
