# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import threading
import subprocess
import os
import ssl
import socket
import time
import errno
import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Union, Dict, cast, Any, Tuple

from proxy.core.event import eventNames, EventQueue
from .handler import HttpProtocolHandlerPlugin
from .exception import HttpProtocolException, ProxyConnectionFailed, ProxyAuthenticationFailed
from .codes import httpStatusCodes
from .parser import HttpParser, httpParserStates, httpParserTypes
from .methods import httpMethods

from ..common.types import HasFileno
from ..common.flags import Flags
from ..common.constants import PROXY_AGENT_HEADER_VALUE
from ..common.utils import build_http_response, text_

from ..core.connection import TcpClientConnection, TcpServerConnection, TcpConnectionUninitializedException

logger = logging.getLogger(__name__)


class HttpProxyBasePlugin(ABC):
    """Base HttpProxyPlugin Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(
            self,
            uid: str,
            flags: Flags,
            client: TcpClientConnection,
            event_queue: EventQueue):
        self.uid = uid                  # pragma: no cover
        self.flags = flags              # pragma: no cover
        self.client = client            # pragma: no cover
        self.event_queue = event_queue  # pragma: no cover

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__      # pragma: no cover

    @abstractmethod
    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Handler called just before Proxy upstream connection is established.

        Return optionally modified request object.
        Raise HttpRequestRejected or HttpProtocolException directly to drop the connection."""
        return request  # pragma: no cover

    @abstractmethod
    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Handler called before dispatching client request to upstream.

        Note: For pipelined (keep-alive) connections, this handler can be
        called multiple times, for each request sent to upstream.

        Note: If TLS interception is enabled, this handler can
        be called multiple times if client exchanges multiple
        requests over same SSL session.

        Return optionally modified request object to dispatch to upstream.
        Return None to drop the request data, e.g. in case a response has already been queued.
        Raise HttpRequestRejected or HttpProtocolException directly to
            teardown the connection with client.
        """
        return request  # pragma: no cover

    @abstractmethod
    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        """Handler called right after receiving raw response from upstream server.

        For HTTPS connections, chunk will be encrypted unless
        TLS interception is also enabled."""
        return chunk  # pragma: no cover

    @abstractmethod
    def on_upstream_connection_close(self) -> None:
        """Handler called right after upstream connection has been closed."""
        pass  # pragma: no cover


class HttpProxyPlugin(HttpProtocolHandlerPlugin):
    """HttpProtocolHandler plugin which implements HttpProxy specifications."""

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = build_http_response(
        httpStatusCodes.OK,
        reason=b'Connection established'
    )

    # Used to synchronize with other HttpProxyPlugin instances while
    # generating certificates
    lock = threading.Lock()

    def __init__(
            self,
            *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.start_time: float = time.time()
        self.server: Optional[TcpServerConnection] = None
        self.response: HttpParser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.pipeline_request: Optional[HttpParser] = None
        self.pipeline_response: Optional[HttpParser] = None

        self.plugins: Dict[str, HttpProxyBasePlugin] = {}
        if b'HttpProxyBasePlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'HttpProxyBasePlugin']:
                instance = klass(
                    self.uid,
                    self.flags,
                    self.client,
                    self.event_queue)
                self.plugins[instance.name()] = instance

    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket]]:
        if not self.request.has_upstream_server():
            return [], []

        r: List[socket.socket] = []
        w: List[socket.socket] = []
        if self.server and not self.server.closed and self.server.connection:
            r.append(self.server.connection)
        if self.server and not self.server.closed and \
                self.server.has_buffer() and self.server.connection:
            w.append(self.server.connection)
        return r, w

    def write_to_descriptors(self, w: List[Union[int, HasFileno]]) -> bool:
        if self.request.has_upstream_server() and \
                self.server and not self.server.closed and \
                self.server.has_buffer() and \
                self.server.connection in w:
            logger.debug('Server is write ready, flushing buffer')
            try:
                self.server.flush()
            except OSError:
                logger.error('OSError when flushing buffer to server')
                return True
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for server')
                return True
        return False

    def read_from_descriptors(self, r: List[Union[int, HasFileno]]) -> bool:
        if self.request.has_upstream_server(
        ) and self.server and not self.server.closed and self.server.connection in r:
            logger.debug('Server is ready for reads, reading...')
            try:
                raw = self.server.recv(self.flags.server_recvbuf_size)
            except ssl.SSLWantReadError:    # Try again later
                # logger.warning('SSLWantReadError encountered while reading from server, will retry ...')
                return False
            except socket.error as e:
                if e.errno == errno.ECONNRESET:
                    logger.warning('Connection reset by upstream: %r' % e)
                else:
                    logger.exception(
                        'Exception while receiving from %s connection %r with reason %r' %
                        (self.server.tag, self.server.connection, e))
                return True

            if not raw:
                logger.debug('Server closed connection, tearing down...')
                return True

            for plugin in self.plugins.values():
                raw = plugin.handle_upstream_chunk(raw)

            # parse incoming response packet
            # only for non-https requests and when
            # tls interception is enabled
            if self.request.method != httpMethods.CONNECT:
                # See https://github.com/abhinavsingh/proxy.py/issues/127 for why
                # currently response parsing is disabled when TLS interception is enabled.
                #
                # or self.config.tls_interception_enabled():
                if self.response.state == httpParserStates.COMPLETE:
                    self.handle_pipeline_response(raw)
                else:
                    self.response.parse(raw)
                    self.emit_response_events()
            else:
                self.response.total_size += len(raw)
            # queue raw data for client
            self.client.queue(raw)
        return False

    def on_client_connection_close(self) -> None:
        if not self.request.has_upstream_server():
            return

        self.access_log()

        # If server was never initialized, return
        if self.server is None:
            return

        # Note that, server instance was initialized
        # but not necessarily the connection object exists.
        # Invoke plugin.on_upstream_connection_close
        for plugin in self.plugins.values():
            plugin.on_upstream_connection_close()

        try:
            try:
                self.server.connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            finally:
                # TODO: Unwrap if wrapped before close?
                self.server.connection.close()
        except TcpConnectionUninitializedException:
            pass
        finally:
            logger.debug(
                'Closed server connection with pending server buffer size %d bytes' %
                self.server.buffer_size())

    def on_response_chunk(self, chunk: bytes) -> bytes:
        # TODO: Allow to output multiple access_log lines
        # for each request over a pipelined HTTP connection (not for HTTPS).
        # However, this must also be accompanied by resetting both request
        # and response objects.
        #
        # if not self.request.method == httpMethods.CONNECT and \
        #         self.response.state == httpParserStates.COMPLETE:
        #     self.access_log()
        return chunk

    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        if not self.request.has_upstream_server():
            return raw

        if self.server and not self.server.closed:
            if self.request.state == httpParserStates.COMPLETE and (
                    self.request.method != httpMethods.CONNECT or
                    self.flags.tls_interception_enabled()):
                if self.pipeline_request is None:
                    self.pipeline_request = HttpParser(
                        httpParserTypes.REQUEST_PARSER)
                self.pipeline_request.parse(raw)
                if self.pipeline_request.state == httpParserStates.COMPLETE:
                    for plugin in self.plugins.values():
                        assert self.pipeline_request is not None
                        r = plugin.handle_client_request(self.pipeline_request)
                        if r is None:
                            return None
                        self.pipeline_request = r
                    assert self.pipeline_request is not None
                    self.server.queue(self.pipeline_request.build())
                    self.pipeline_request = None
            else:
                self.server.queue(raw)
            return None
        else:
            return raw

    def on_request_complete(self) -> Union[socket.socket, bool]:
        if not self.request.has_upstream_server():
            return False

        self.emit_request_complete()

        self.authenticate()

        # Note: can raise HttpRequestRejected exception
        # Invoke plugin.before_upstream_connection
        do_connect = True
        for plugin in self.plugins.values():
            r = plugin.before_upstream_connection(self.request)
            if r is None:
                do_connect = False
                break
            self.request = r

        if do_connect:
            self.connect_upstream()

        for plugin in self.plugins.values():
            assert self.request is not None
            r = plugin.handle_client_request(self.request)
            if r is not None:
                self.request = r
            else:
                return False

        if self.request.method == httpMethods.CONNECT:
            self.client.queue(
                HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
            # If interception is enabled
            if self.flags.tls_interception_enabled():
                # Perform SSL/TLS handshake with upstream
                self.wrap_server()
                # Generate certificate and perform handshake with client
                try:
                    # wrap_client also flushes client data before wrapping
                    # sending to client can raise, handle expected exceptions
                    self.wrap_client()
                except OSError:
                    logger.error('OSError when wrapping client')
                    return True
                except BrokenPipeError:
                    logger.error(
                        'BrokenPipeError when wrapping client')
                    return True
                # Update all plugin connection reference
                for plugin in self.plugins.values():
                    plugin.client._conn = self.client.connection
                return self.client.connection
        elif self.server:
            # - proxy-connection header is a mistake, it doesn't seem to be
            #   officially documented in any specification, drop it.
            # - proxy-authorization is of no use for upstream, remove it.
            self.request.del_headers(
                [b'proxy-authorization', b'proxy-connection'])
            # - For HTTP/1.0, connection header defaults to close
            # - For HTTP/1.1, connection header defaults to keep-alive
            # Respect headers sent by client instead of manipulating
            # Connection or Keep-Alive header.  However, note that per
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
            # connection headers are meant for communication between client and
            # first intercepting proxy.
            self.request.add_headers(
                [(b'Via', b'1.1 %s' % PROXY_AGENT_HEADER_VALUE)])
            # Disable args.disable_headers before dispatching to upstream
            self.server.queue(
                self.request.build(
                    disable_headers=self.flags.disable_headers))
        return False

    def handle_pipeline_response(self, raw: bytes) -> None:
        if self.pipeline_response is None:
            self.pipeline_response = HttpParser(
                httpParserTypes.RESPONSE_PARSER)
        self.pipeline_response.parse(raw)
        if self.pipeline_response.state == httpParserStates.COMPLETE:
            self.pipeline_response = None

    def access_log(self) -> None:
        server_host, server_port = self.server.addr if self.server else (
            None, None)
        connection_time_ms = (time.time() - self.start_time) * 1000
        if self.request.method == b'CONNECT':
            logger.info(
                '%s:%s - %s %s:%s - %s bytes - %.2f ms' %
                (self.client.addr[0],
                 self.client.addr[1],
                 text_(self.request.method),
                 text_(server_host),
                 text_(server_port),
                 self.response.total_size,
                 connection_time_ms))
        elif self.request.method:
            logger.info(
                '%s:%s - %s %s:%s%s - %s %s - %s bytes - %.2f ms' %
                (self.client.addr[0], self.client.addr[1],
                 text_(self.request.method),
                 text_(server_host), server_port,
                 text_(self.request.path),
                 text_(self.response.code),
                 text_(self.response.reason),
                 self.response.total_size,
                 connection_time_ms))

    @staticmethod
    def generated_cert_file_path(ca_cert_dir: str, host: str) -> str:
        return os.path.join(ca_cert_dir, '%s.pem' % host)

    def generate_upstream_certificate(
            self, _certificate: Optional[Dict[str, Any]]) -> str:
        if not (self.flags.ca_cert_dir and self.flags.ca_signing_key_file and
                self.flags.ca_cert_file and self.flags.ca_key_file):
            raise HttpProtocolException(
                f'For certificate generation all the following flags are mandatory: '
                f'--ca-cert-file:{ self.flags.ca_cert_file }, '
                f'--ca-key-file:{ self.flags.ca_key_file }, '
                f'--ca-signing-key-file:{ self.flags.ca_signing_key_file }')
        cert_file_path = HttpProxyPlugin.generated_cert_file_path(
            self.flags.ca_cert_dir, text_(self.request.host))
        with self.lock:
            if not os.path.isfile(cert_file_path):
                logger.debug('Generating certificates %s', cert_file_path)
                # TODO: Parse subject from certificate
                # Currently we only set CN= field for generated certificates.
                gen_cert = subprocess.Popen(
                    ['openssl', 'req', '-new', '-key', self.flags.ca_signing_key_file, '-subj',
                     f'/C=/ST=/L=/O=/OU=/CN={ text_(self.request.host) }'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                sign_cert = subprocess.Popen(
                    ['openssl', 'x509', '-req', '-days', '365', '-CA', self.flags.ca_cert_file, '-CAkey',
                     self.flags.ca_key_file, '-set_serial', str(int(time.time())), '-out', cert_file_path],
                    stdin=gen_cert.stdout,
                    stderr=subprocess.PIPE)
                # TODO: Ensure sign_cert success.
                sign_cert.communicate(timeout=10)
        return cert_file_path

    def wrap_server(self) -> None:
        assert self.server is not None
        assert isinstance(self.server.connection, socket.socket)
        ctx = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH)
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        self.server.connection.setblocking(True)
        self.server._conn = ctx.wrap_socket(
            self.server.connection,
            server_hostname=text_(self.request.host))
        self.server.connection.setblocking(False)

    def wrap_client(self) -> None:
        assert self.server is not None
        assert isinstance(self.server.connection, ssl.SSLSocket)
        generated_cert = self.generate_upstream_certificate(
            cast(Dict[str, Any], self.server.connection.getpeercert()))
        self.client.connection.setblocking(True)
        self.client.flush()
        self.client._conn = ssl.wrap_socket(
            self.client.connection,
            server_side=True,
            keyfile=self.flags.ca_signing_key_file,
            certfile=generated_cert)
        self.client.connection.setblocking(False)
        logger.debug(
            'TLS interception using %s', generated_cert)

    def authenticate(self) -> None:
        if self.flags.auth_code:
            if b'proxy-authorization' not in self.request.headers or \
                    self.request.headers[b'proxy-authorization'][1] != self.flags.auth_code:
                raise ProxyAuthenticationFailed()

    def connect_upstream(self) -> None:
        host, port = self.request.host, self.request.port
        if host and port:
            self.server = TcpServerConnection(text_(host), port)
            try:
                logger.debug(
                    'Connecting to upstream %s:%s' %
                    (text_(host), port))
                self.server.connect()
                self.server.connection.setblocking(False)
                logger.debug(
                    'Connected to upstream %s:%s' %
                    (text_(host), port))
            except Exception as e:  # TimeoutError, socket.gaierror
                self.server.closed = True
                raise ProxyConnectionFailed(text_(host), port, repr(e)) from e
        else:
            logger.exception('Both host and port must exist')
            raise HttpProtocolException()

    def emit_request_complete(self) -> None:
        if not self.flags.enable_events:
            return

        assert self.request.path
        assert self.request.port
        self.event_queue.publish(
            request_id=self.uid,
            event_name=eventNames.REQUEST_COMPLETE,
            event_payload={
                'url': text_(self.request.path)
                if self.request.method == httpMethods.CONNECT
                else 'http://%s:%d%s' % (text_(self.request.host), self.request.port, text_(self.request.path)),
                'method': text_(self.request.method),
                'headers': {text_(k): text_(v[1]) for k, v in self.request.headers.items()},
                'body': text_(self.request.body)
                if self.request.method == httpMethods.POST
                else None
            },
            publisher_id=self.__class__.__name__
        )

    def emit_response_events(self) -> None:
        if not self.flags.enable_events:
            return

        if self.response.state == httpParserStates.COMPLETE:
            self.emit_response_complete()
        elif self.response.state == httpParserStates.RCVING_BODY:
            self.emit_response_chunk_received()
        elif self.response.state == httpParserStates.HEADERS_COMPLETE:
            self.emit_response_headers_complete()

    def emit_response_headers_complete(self) -> None:
        if not self.flags.enable_events:
            return

    def emit_response_chunk_received(self) -> None:
        if not self.flags.enable_events:
            return

    def emit_response_complete(self) -> None:
        if not self.flags.enable_events:
            return
