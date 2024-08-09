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
from typing import Any, List, Type, Tuple, Optional

from .parser import HttpParser, httpParserTypes, httpParserStates
from .plugin import HttpProtocolHandlerPlugin
from .exception import HttpProtocolException
from .protocols import httpProtocols
from .responses import BAD_REQUEST_RESPONSE_PKT
from ..core.base import BaseTcpServerHandler
from .connection import HttpClientConnection
from ..common.types import Readables, Writables, SelectableEvents
from ..common.constants import DEFAULT_SELECTOR_SELECT_TIMEOUT


logger = logging.getLogger(__name__)


class HttpProtocolHandler(BaseTcpServerHandler[HttpClientConnection]):
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
        self.writes_teared: bool = False
        self.reads_teared: bool = False

    ##
    # initialize, is_inactive, shutdown, get_events, handle_events
    # overrides Work class definitions.
    ##

    @staticmethod
    def create(*args: Any) -> HttpClientConnection:  # pragma: no cover
        return HttpClientConnection(*args)

    def initialize(self) -> None:
        super().initialize()
        if self._encryption_enabled():
            self.work = HttpClientConnection(
                conn=self.work.connection,
                addr=self.work.addr,
            )

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

    async def get_events(self) -> SelectableEvents:
        # Get default client events
        events: SelectableEvents = await super().get_events()
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
        self.writes_teared = await self.handle_writables(writables)
        if self.writes_teared:
            return True
        # Invoke plugin.write_to_descriptors
        if self.plugin:
            self.writes_teared = await self.plugin.write_to_descriptors(writables)
            if self.writes_teared:
                return True
        # Read from ready to read sockets if reads have not already teared down
        if not self.reads_teared:
            self.reads_teared = await self.handle_readables(readables)
            if not self.reads_teared:
                # Invoke plugin.read_from_descriptors
                if self.plugin:
                    self.reads_teared = await self.plugin.read_from_descriptors(
                        readables,
                    )
        # Wait until client buffer has flushed when reads has teared down but we can still write
        if self.reads_teared and not self.work.has_buffer():
            return True
        return False

    def handle_data(self, data: memoryview) -> Optional[bool]:
        """Handles incoming data from client."""
        if data is None:
            logger.debug('Client closed connection, tearing down...')
            self.work.closed = True
            return True
        try:
            # We don't parse incoming data any further after 1st HTTP request packet.
            #
            # Plugins can utilize on_client_data for such cases and
            # apply custom logic to handle request data sent after 1st
            # valid request.
            if self.request.state != httpParserStates.COMPLETE:
                if self._parse_first_request(data):
                    return True
            # HttpProtocolHandlerPlugin.on_client_data
            # Can raise HttpProtocolException to tear down the connection
            elif self.plugin:
                self.plugin.on_client_data(data)
        except HttpProtocolException as e:
            logger.warning('HttpProtocolException: %s' % e)
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
                logger.warning(     # pragma: no cover
                    'BrokenPipeError when flushing buffer for client',
                )
                return True
            except OSError as exc:
                logger.exception(  # pragma: no cover
                    'OSError when flushing buffer to client',
                    exc_info=exc,
                )
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
                        exc_info=True,
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
        try:
            self.request.parse(data)
        except HttpProtocolException as e:  # noqa: WPS329
            self.work.queue(BAD_REQUEST_RESPONSE_PKT)
            raise e
        except Exception as e:
            self.work.queue(BAD_REQUEST_RESPONSE_PKT)
            raise HttpProtocolException(
                'Error when parsing request: %r' % data.tobytes(),
            ) from e
        if not self.request.is_complete:
            return False
        # Bail out if http protocol is unknown
        if self.request.http_handler_protocol == httpProtocols.UNKNOWN:
            self.work.queue(BAD_REQUEST_RESPONSE_PKT)
            return True
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
            if self.selector:
                self.selector.close()
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
    async def _selected_events(self) -> Tuple[SelectableEvents, Readables, Writables]:
        assert self.selector
        events = await self.get_events()
        for fd in events:
            self.selector.register(fd, events[fd])
        ev = self.selector.select(timeout=DEFAULT_SELECTOR_SELECT_TIMEOUT)
        readables = []
        writables = []
        for key, mask in ev:
            if mask & selectors.EVENT_READ:
                readables.append(key.fd)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fd)
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
                self.work.flush(self.flags.max_sendbuf_size)
        except BrokenPipeError:
            pass
        finally:
            self.selector.unregister(self.work.connection)
