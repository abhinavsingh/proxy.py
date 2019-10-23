# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

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
from abc import ABC, abstractmethod
from typing import Tuple, List, Union, Optional, Generator, Dict

from .common.flags import Flags
from .common.types import HasFileno
from .core.acceptor import ThreadlessWork
from .core.connection import TcpClientConnection
from .http.parser import HttpParser, httpParserStates, httpParserTypes
from .http.exception import HttpProtocolException

logger = logging.getLogger(__name__)


class ProtocolHandlerPlugin(ABC):
    """Base ProtocolHandler Plugin class.

    NOTE: This is an internal plugin and in most cases only useful for core contributors.
    If you are looking for proxy server plugins see `<proxy.HttpProxyBasePlugin>`.

    Implements various lifecycle events for an accepted client connection.
    Following events are of interest:

    1. Client Connection Accepted
       A new plugin instance is created per accepted client connection.
       Add your logic within __init__ constructor for any per connection setup.
    2. Client Request Chunk Received
       on_client_data is called for every chunk of data sent by the client.
    3. Client Request Complete
       on_request_complete is called once client request has completed.
    4. Server Response Chunk Received
       on_response_chunk is called for every chunk received from the server.
    5. Client Connection Closed
       Add your logic within `on_client_connection_close` for any per connection teardown.
    """

    def __init__(
            self,
            config: Flags,
            client: TcpClientConnection,
            request: HttpParser):
        self.config: Flags = config
        self.client: TcpClientConnection = client
        self.request: HttpParser = request
        super().__init__()

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__

    @abstractmethod
    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []  # pragma: no cover

    @abstractmethod
    def write_to_descriptors(self, w: List[Union[int, HasFileno]]) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def read_from_descriptors(self, r: List[Union[int, HasFileno]]) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        return raw  # pragma: no cover

    @abstractmethod
    def on_request_complete(self) -> Union[socket.socket, bool]:
        """Called right after client request parser has reached COMPLETE state."""
        pass  # pragma: no cover

    @abstractmethod
    def on_response_chunk(self, chunk: bytes) -> bytes:
        """Handle data chunks as received from the server.

        Return optionally modified chunk to return back to client."""
        return chunk  # pragma: no cover

    @abstractmethod
    def on_client_connection_close(self) -> None:
        pass  # pragma: no cover


class ProtocolHandler(ThreadlessWork):
    """HTTP, HTTPS, HTTP2, WebSockets protocol handler.

    Accepts `Client` connection object and manages ProtocolHandlerPlugin invocations.
    """

    def __init__(self, fileno: int, addr: Tuple[str, int],
                 flags: Optional[Flags] = None):
        super().__init__(fileno, addr, flags)

        self.start_time: float = time.time()
        self.last_activity: float = self.start_time
        self.request: HttpParser = HttpParser(httpParserTypes.REQUEST_PARSER)
        self.response: HttpParser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.selector = selectors.DefaultSelector()
        self.client: TcpClientConnection = TcpClientConnection(
            self.fromfd(self.fileno), self.addr
        )
        self.plugins: Dict[str, ProtocolHandlerPlugin] = {}

    def initialize(self) -> None:
        """Optionally upgrades connection to HTTPS, set conn in non-blocking mode and initializes plugins."""
        conn = self.optionally_wrap_socket(self.client.connection)
        conn.setblocking(False)
        if self.flags.encryption_enabled():
            self.client = TcpClientConnection(conn=conn, addr=self.addr)
        if b'ProtocolHandlerPlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'ProtocolHandlerPlugin']:
                instance = klass(self.flags, self.client, self.request)
                self.plugins[instance.name()] = instance
        logger.debug('Handling connection %r' % self.client.connection)

    def is_inactive(self) -> bool:
        if not self.client.has_buffer() and \
                self.connection_inactive_for() > self.flags.timeout:
            return True
        return False

    def get_events(self) -> Dict[socket.socket, int]:
        events: Dict[socket.socket, int] = {
            self.client.connection: selectors.EVENT_READ
        }
        if self.client.has_buffer():
            events[self.client.connection] |= selectors.EVENT_WRITE

        # ProtocolHandlerPlugin.get_descriptors
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

    def handle_events(
            self,
            readables: List[Union[int, HasFileno]],
            writables: List[Union[int, HasFileno]]) -> bool:
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

    def shutdown(self) -> None:
        # Flush pending buffer if any
        self.flush()

        # Invoke plugin.on_client_connection_close
        for plugin in self.plugins.values():
            plugin.on_client_connection_close()

        logger.debug(
            'Closing client connection %r '
            'at address %r with pending client buffer size %d bytes' %
            (self.client.connection, self.client.addr, self.client.buffer_size()))

        conn = self.client.connection
        try:
            # Unwrap if wrapped before shutdown.
            if self.flags.encryption_enabled() and \
                    isinstance(self.client.connection, ssl.SSLSocket):
                conn = self.client.connection.unwrap()
            conn.shutdown(socket.SHUT_WR)
            logger.debug('Client connection shutdown successful')
        except OSError:
            pass
        finally:
            conn.close()
            logger.debug('Client connection closed')

    def fromfd(self, fileno: int) -> socket.socket:
        conn = socket.fromfd(
            fileno, family=socket.AF_INET if self.flags.hostname.version == 4 else socket.AF_INET6,
            type=socket.SOCK_STREAM)
        return conn

    def optionally_wrap_socket(
            self, conn: socket.socket) -> Union[ssl.SSLSocket, socket.socket]:
        """Attempts to wrap accepted client connection using provided certificates.

        Shutdown and closes client connection upon error.
        """
        if self.flags.encryption_enabled():
            ctx = ssl.create_default_context(
                ssl.Purpose.CLIENT_AUTH)
            ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            ctx.verify_mode = ssl.CERT_NONE
            assert self.flags.keyfile and self.flags.certfile
            ctx.load_cert_chain(
                certfile=self.flags.certfile,
                keyfile=self.flags.keyfile)
            conn = ctx.wrap_socket(conn, server_side=True)
        return conn

    def connection_inactive_for(self) -> float:
        return time.time() - self.last_activity

    def flush(self) -> None:
        if not self.client.has_buffer():
            return
        try:
            self.selector.register(self.client.connection, selectors.EVENT_WRITE)
            while self.client.has_buffer():
                ev: List[Tuple[selectors.SelectorKey, int]] = self.selector.select(timeout=1)
                if len(ev) == 0:
                    continue
                self.client.flush()
        except BrokenPipeError:
            pass
        finally:
            self.selector.unregister(self.client.connection)

    def handle_writables(self, writables: List[Union[int, HasFileno]]) -> bool:
        if self.client.buffer_size() > 0 and self.client.connection in writables:
            logger.debug('Client is ready for writes, flushing buffer')
            self.last_activity = time.time()

            # Invoke plugin.on_response_chunk
            chunk = self.client.buffer
            for plugin in self.plugins.values():
                chunk = plugin.on_response_chunk(chunk)
                if chunk is None:
                    break

            try:
                self.client.flush()
            except OSError:
                logger.error('OSError when flushing buffer to client')
                return True
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for client')
                return True
        return False

    def handle_readables(self, readables: List[Union[int, HasFileno]]) -> bool:
        if self.client.connection in readables:
            logger.debug('Client is ready for reads, reading')
            self.last_activity = time.time()
            try:
                client_data = self.client.recv(self.flags.client_recvbuf_size)
            except ssl.SSLWantReadError:    # Try again later
                logger.warning('SSLWantReadError encountered while reading from client, will retry ...')
                return False
            except socket.error as e:
                if e.errno == errno.ECONNRESET:
                    logger.warning('%r' % e)
                else:
                    logger.exception(
                        'Exception while receiving from %s connection %r with reason %r' %
                        (self.client.tag, self.client.connection, e))
                return True

            if not client_data:
                logger.debug('Client closed connection, tearing down...')
                self.client.closed = True
                return True

            try:
                # ProtocolHandlerPlugin.on_client_data
                # Can raise HttpProtocolException to teardown the connection
                plugin_index = 0
                plugins = list(self.plugins.values())
                while plugin_index < len(plugins) and client_data:
                    client_data = plugins[plugin_index].on_client_data(client_data)
                    if client_data is None:
                        break
                    plugin_index += 1

                # Don't parse request any further after 1st request has completed.
                # This specially does happen for pipeline requests.
                # Plugins can utilize on_client_data for such cases and
                # apply custom logic to handle request data sent after 1st valid request.
                if client_data and self.request.state != httpParserStates.COMPLETE:
                    # Parse http request
                    self.request.parse(client_data)
                    if self.request.state == httpParserStates.COMPLETE:
                        # Invoke plugin.on_request_complete
                        for plugin in self.plugins.values():
                            upgraded_sock = plugin.on_request_complete()
                            if isinstance(upgraded_sock, ssl.SSLSocket):
                                logger.debug(
                                    'Updated client conn to %s', upgraded_sock)
                                self.client._conn = upgraded_sock
                                for plugin_ in self.plugins.values():
                                    if plugin_ != plugin:
                                        plugin_.client._conn = upgraded_sock
                            elif isinstance(upgraded_sock, bool) and upgraded_sock is True:
                                return True
            except HttpProtocolException as e:
                logger.exception(
                    'HttpProtocolException type raised', exc_info=e)
                response = e.response(self.request)
                if response:
                    self.client.queue(response)
                return True
        return False

    @contextlib.contextmanager
    def selected_events(self) -> \
            Generator[Tuple[List[Union[int, HasFileno]],
                            List[Union[int, HasFileno]]],
                      None, None]:
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
        for fd in events.keys():
            self.selector.unregister(fd)

    def run_once(self) -> bool:
        with self.selected_events() as (readables, writables):
            teardown = self.handle_events(readables, writables)
            if teardown:
                return True
            return False

    def run(self) -> None:
        try:
            self.initialize()
            while True:
                # Teardown if client buffer is empty and connection is inactive
                if self.is_inactive():
                    logger.debug(
                        'Client buffer is empty and maximum inactivity has reached '
                        'between client and server connection, tearing down...')
                    break
                teardown = self.run_once()
                if teardown:
                    break
        except KeyboardInterrupt:  # pragma: no cover
            pass
        except ssl.SSLError as e:
            logger.exception('ssl.SSLError', exc_info=e)
        except Exception as e:
            logger.exception(
                'Exception while handling connection %r' %
                self.client.connection, exc_info=e)
        finally:
            self.shutdown()
