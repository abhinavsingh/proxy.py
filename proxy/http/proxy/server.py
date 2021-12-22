# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       http
       reusability
"""
import os
import ssl
import time
import errno
import socket
import logging
import threading
import subprocess

from typing import Optional, List, Union, Dict, cast, Any, Tuple

from .plugin import HttpProxyBasePlugin

from ..headers import httpHeaders
from ..methods import httpMethods
from ..codes import httpStatusCodes
from ..plugin import HttpProtocolHandlerPlugin
from ..exception import HttpProtocolException, ProxyConnectionFailed
from ..parser import HttpParser, httpParserStates, httpParserTypes
# from ..parser.tls import TlsParser, TlsHandshake, tlsContentType, tlsHandshakeType

from ...common.types import Readables, Writables
from ...common.constants import DEFAULT_CA_CERT_DIR, DEFAULT_CA_CERT_FILE, DEFAULT_CA_FILE
from ...common.constants import DEFAULT_CA_KEY_FILE, DEFAULT_CA_SIGNING_KEY_FILE
from ...common.constants import COMMA, DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_CERT_FILE
from ...common.constants import PROXY_AGENT_HEADER_VALUE, DEFAULT_DISABLE_HEADERS
from ...common.constants import DEFAULT_HTTP_ACCESS_LOG_FORMAT, DEFAULT_HTTPS_ACCESS_LOG_FORMAT
from ...common.constants import DEFAULT_DISABLE_HTTP_PROXY, PLUGIN_PROXY_AUTH
from ...common.utils import build_http_response, text_
from ...common.pki import gen_public_key, gen_csr, sign_csr

from ...core.event import eventNames
from ...core.connection import TcpServerConnection, ConnectionPool
from ...core.connection import TcpConnectionUninitializedException
from ...common.flag import flags

logger = logging.getLogger(__name__)


flags.add_argument(
    '--server-recvbuf-size',
    type=int,
    default=DEFAULT_SERVER_RECVBUF_SIZE,
    help='Default: 1 MB. Maximum amount of data received from the '
    'server in a single recv() operation. Bump this '
    'value for faster downloads at the expense of '
    'increased RAM.',
)

flags.add_argument(
    '--disable-http-proxy',
    action='store_true',
    default=DEFAULT_DISABLE_HTTP_PROXY,
    help='Default: False.  Whether to disable proxy.HttpProxyPlugin.',
)

flags.add_argument(
    '--disable-headers',
    type=str,
    default=COMMA.join(DEFAULT_DISABLE_HEADERS),
    help='Default: None.  Comma separated list of headers to remove before '
    'dispatching client request to upstream server.',
)

flags.add_argument(
    '--ca-key-file',
    type=str,
    default=DEFAULT_CA_KEY_FILE,
    help='Default: None. CA key to use for signing dynamically generated '
    'HTTPS certificates.  If used, must also pass --ca-cert-file and --ca-signing-key-file',
)

flags.add_argument(
    '--ca-cert-dir',
    type=str,
    default=DEFAULT_CA_CERT_DIR,
    help='Default: ~/.proxy/certificates. Directory to store dynamically generated certificates. '
    'Also see --ca-key-file, --ca-cert-file and --ca-signing-key-file',
)

flags.add_argument(
    '--ca-cert-file',
    type=str,
    default=DEFAULT_CA_CERT_FILE,
    help='Default: None. Signing certificate to use for signing dynamically generated '
    'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-signing-key-file',
)

flags.add_argument(
    '--ca-file',
    type=str,
    default=str(DEFAULT_CA_FILE),
    help='Default: ' + str(DEFAULT_CA_FILE) +
    '. Provide path to custom CA bundle for peer certificate verification',
)

flags.add_argument(
    '--ca-signing-key-file',
    type=str,
    default=DEFAULT_CA_SIGNING_KEY_FILE,
    help='Default: None. CA signing key to use for dynamic generation of '
    'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-cert-file',
)

flags.add_argument(
    '--cert-file',
    type=str,
    default=DEFAULT_CERT_FILE,
    help='Default: None. Server certificate to enable end-to-end TLS encryption with clients. '
    'If used, must also pass --key-file.',
)

flags.add_argument(
    '--auth-plugin',
    type=str,
    default=PLUGIN_PROXY_AUTH,
    help='Default: ' + PLUGIN_PROXY_AUTH + '.  ' +
    'Auth plugin to use instead of default basic auth plugin.',
)


class HttpProxyPlugin(HttpProtocolHandlerPlugin):
    """HttpProtocolHandler plugin which implements HttpProxy specifications."""

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = memoryview(
        build_http_response(
            httpStatusCodes.OK,
            reason=b'Connection established',
        ),
    )

    # Used to synchronization during certificate generation and
    # connection pool operations.
    lock = threading.Lock()

    # Shared connection pool
    pool = ConnectionPool()

    def __init__(
            self,
            *args: Any, **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.start_time: float = time.time()
        self.upstream: Optional[TcpServerConnection] = None
        self.response: HttpParser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.pipeline_request: Optional[HttpParser] = None
        self.pipeline_response: Optional[HttpParser] = None

        self.plugins: Dict[str, HttpProxyBasePlugin] = {}
        if b'HttpProxyBasePlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'HttpProxyBasePlugin']:
                instance: HttpProxyBasePlugin = klass(
                    self.uid,
                    self.flags,
                    self.client,
                    self.event_queue,
                )
                self.plugins[instance.name()] = instance

    def tls_interception_enabled(self) -> bool:
        return self.flags.ca_key_file is not None and \
            self.flags.ca_cert_dir is not None and \
            self.flags.ca_signing_key_file is not None and \
            self.flags.ca_cert_file is not None

    def get_descriptors(self) -> Tuple[List[int], List[int]]:
        if not self.request.has_host():
            return [], []
        r: List[int] = []
        w: List[int] = []
        if (
            self.upstream and
            not self.upstream.closed and
            self.upstream.connection
        ):
            r.append(self.upstream.connection.fileno())
        if (
            self.upstream and
            not self.upstream.closed and
            self.upstream.has_buffer() and
            self.upstream.connection
        ):
            w.append(self.upstream.connection.fileno())
        # TODO(abhinavsingh): We need to keep a mapping of plugin and
        # descriptors registered by them, so that within write/read blocks
        # we can invoke the right plugin callbacks.
        for plugin in self.plugins.values():
            plugin_read_desc, plugin_write_desc = plugin.get_descriptors()
            r.extend(plugin_read_desc)
            w.extend(plugin_write_desc)
        return r, w

    def _close_and_release(self) -> bool:
        if self.flags.enable_conn_pool:
            assert self.upstream and not self.upstream.closed
            self.upstream.closed = True
            with self.lock:
                self.pool.release(self.upstream)
            self.upstream = None
        return True

    async def write_to_descriptors(self, w: Writables) -> bool:
        if (self.upstream and self.upstream.connection.fileno() not in w) or not self.upstream:
            # Currently, we just call write/read block of each plugins.  It is
            # plugins responsibility to ignore this callback, if passed descriptors
            # doesn't contain the descriptor they registered.
            for plugin in self.plugins.values():
                teardown = plugin.write_to_descriptors(w)
                if teardown:
                    return True
        elif self.request.has_host() and \
                self.upstream and not self.upstream.closed and \
                self.upstream.has_buffer() and \
                self.upstream.connection.fileno() in w:
            logger.debug('Server is write ready, flushing buffer')
            try:
                self.upstream.flush()
            except ssl.SSLWantWriteError:
                logger.warning(
                    'SSLWantWriteError while trying to flush to server, will retry',
                )
                return False
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for server',
                )
                return self._close_and_release()
            except OSError as e:
                logger.exception(
                    'OSError when flushing buffer to server', exc_info=e,
                )
                return self._close_and_release()
        return False

    async def read_from_descriptors(self, r: Readables) -> bool:
        if (
            self.upstream and not
            self.upstream.closed and
            self.upstream.connection.fileno() not in r
        ) or not self.upstream:
            # Currently, we just call write/read block of each plugins.  It is
            # plugins responsibility to ignore this callback, if passed descriptors
            # doesn't contain the descriptor they registered for.
            for plugin in self.plugins.values():
                teardown = plugin.read_from_descriptors(r)
                if teardown:
                    return True
        elif self.request.has_host() \
                and self.upstream \
                and not self.upstream.closed \
                and self.upstream.connection.fileno() in r:
            logger.debug('Server is ready for reads, reading...')
            try:
                raw = self.upstream.recv(self.flags.server_recvbuf_size)
            except TimeoutError as e:
                self._close_and_release()
                if e.errno == errno.ETIMEDOUT:
                    logger.warning(
                        '%s:%d timed out on recv' %
                        self.upstream.addr,
                    )
                    return True
                raise e
            except ssl.SSLWantReadError:    # Try again later
                # logger.warning('SSLWantReadError encountered while reading from server, will retry ...')
                return False
            except OSError as e:
                if e.errno == errno.EHOSTUNREACH:
                    logger.warning(
                        '%s:%d unreachable on recv' %
                        self.upstream.addr,
                    )
                if e.errno == errno.ECONNRESET:
                    logger.warning(
                        'Connection reset by upstream: {0}:{1}'.format(
                            *self.upstream.addr,
                        ),
                    )
                else:
                    logger.warning(
                        'Exception while receiving from %s connection#%d with reason %r' %
                        (self.upstream.tag, self.upstream.connection.fileno(), e),
                    )
                return self._close_and_release()

            if raw is None:
                if self.upstream.closed:
                    logger.debug('Server closed connection, tearing down...')
                    return self._close_and_release()
                return False
            for plugin in self.plugins.values():
                raw = plugin.handle_upstream_chunk(raw)

            # parse incoming response packet
            # only for non-https requests and when
            # tls interception is enabled
            if not self.request.is_https_tunnel \
                    or self.tls_interception_enabled():
                if self.response.is_complete:
                    self.handle_pipeline_response(raw)
                else:
                    # TODO(abhinavsingh): Remove .tobytes after parser is
                    # memoryview compliant
                    chunk = raw.tobytes()
                    self.response.parse(chunk)
                    self.emit_response_events(len(chunk))
            else:
                self.response.total_size += len(raw)
            # queue raw data for client
            self.client.queue(raw)
        return False

    def on_client_connection_close(self) -> None:
        if not self.request.has_host():
            return

        context = {
            'client_ip': None if not self.client.addr else self.client.addr[0],
            'client_port': None if not self.client.addr else self.client.addr[1],
            'server_host': text_(self.upstream.addr[0] if self.upstream else None),
            'server_port': text_(self.upstream.addr[1] if self.upstream else None),
            'connection_time_ms': '%.2f' % ((time.time() - self.start_time) * 1000),
            # Request
            'request_method': text_(self.request.method),
            'request_path': text_(self.request.path),
            'request_bytes': self.request.total_size,
            'request_ua': self.request.header(b'user-agent')
            if self.request.has_header(b'user-agent')
            else None,
            'request_version': self.request.version,
            # Response
            'response_bytes': self.response.total_size,
            'response_code': text_(self.response.code),
            'response_reason': text_(self.response.reason),
        }
        if self.flags.enable_proxy_protocol:
            assert self.request.protocol and self.request.protocol.family
            context.update({
                'protocol': {
                    'family': text_(self.request.protocol.family),
                },
            })
            if self.request.protocol.source:
                context.update({
                    'protocol': {
                        'source_ip': text_(self.request.protocol.source[0]),
                        'source_port': self.request.protocol.source[1],
                    },
                })
            if self.request.protocol.destination:
                context.update({
                    'protocol': {
                        'destination_ip': text_(self.request.protocol.destination[0]),
                        'destination_port': self.request.protocol.destination[1],
                    },
                })

        log_handled = False
        for plugin in self.plugins.values():
            ctx = plugin.on_access_log(context)
            if ctx is None:
                log_handled = True
                break
            context = ctx
        if not log_handled:
            self.access_log(context)

        # Note that, server instance was initialized
        # but not necessarily the connection object exists.
        #
        # Unfortunately this is still being called when an upstream
        # server connection was never established.  This is done currently
        # to assist proxy pool plugin to close its upstream proxy connections.
        #
        # In short, treat on_upstream_connection_close as on_client_connection_close
        # equivalent within proxy plugins.
        #
        # Invoke plugin.on_upstream_connection_close
        for plugin in self.plugins.values():
            plugin.on_upstream_connection_close()

        # If server was never initialized or was _close_and_release
        if self.upstream is None:
            return

        if self.flags.enable_conn_pool:
            # Release the connection for reusability
            with self.lock:
                self.pool.release(self.upstream)
            return

        try:
            try:
                self.upstream.connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            finally:
                # TODO: Unwrap if wrapped before close?
                self.upstream.connection.close()
        except TcpConnectionUninitializedException:
            pass
        finally:
            logger.debug(
                'Closed server connection, has buffer %s' %
                self.upstream.has_buffer(),
            )

    def access_log(self, log_attrs: Dict[str, Any]) -> None:
        access_log_format = DEFAULT_HTTPS_ACCESS_LOG_FORMAT
        if not self.request.is_https_tunnel:
            access_log_format = DEFAULT_HTTP_ACCESS_LOG_FORMAT
        logger.info(access_log_format.format_map(log_attrs))

    def on_response_chunk(self, chunk: List[memoryview]) -> List[memoryview]:
        # TODO: Allow to output multiple access_log lines
        # for each request over a pipelined HTTP connection (not for HTTPS).
        # However, this must also be accompanied by resetting both request
        # and response objects.
        #
        # if not self.request.is_https_tunnel and \
        #         self.response.is_complete:
        #     self.access_log()
        return chunk

    # Can return None to tear down connection
    def on_client_data(self, raw: memoryview) -> Optional[memoryview]:
        if not self.request.has_host():
            return raw

        # For scenarios when an upstream connection was never established,
        # let plugin do whatever they wish to.  These are special scenarios
        # where plugins are trying to do something magical.  Within the core
        # we don't know the context.  In fact, we are not even sure if data
        # exchanged is http spec compliant.
        #
        # Hence, here we pass raw data to HTTP proxy plugins as is.
        #
        # We only call handle_client_data once original request has been
        # completely received
        if not self.upstream:
            for plugin in self.plugins.values():
                o = plugin.handle_client_data(raw)
                if o is None:
                    return None
                raw = o
        elif self.upstream and not self.upstream.closed:
            # For http proxy requests, handle pipeline case.
            # We also handle pipeline scenario for https proxy
            # requests is TLS interception is enabled.
            if self.request.is_complete and (
                    not self.request.is_https_tunnel or
                    self.tls_interception_enabled()
            ):
                if self.pipeline_request is not None and \
                        self.pipeline_request.is_connection_upgrade:
                    # Previous pipelined request was a WebSocket
                    # upgrade request. Incoming client data now
                    # must be treated as WebSocket protocol packets.
                    self.upstream.queue(raw)
                    return None

                if self.pipeline_request is None:
                    # For pipeline requests, we never
                    # want to use --enable-proxy-protocol flag
                    # as proxy protocol header will not be present
                    self.pipeline_request = HttpParser(
                        httpParserTypes.REQUEST_PARSER,
                    )

                # TODO(abhinavsingh): Remove .tobytes after parser is
                # memoryview compliant
                self.pipeline_request.parse(raw.tobytes())
                if self.pipeline_request.is_complete:
                    for plugin in self.plugins.values():
                        assert self.pipeline_request is not None
                        r = plugin.handle_client_request(self.pipeline_request)
                        if r is None:
                            return None
                        self.pipeline_request = r
                    assert self.pipeline_request is not None
                    # TODO(abhinavsingh): Remove memoryview wrapping here after
                    # parser is fully memoryview compliant
                    self.upstream.queue(
                        memoryview(
                            self.pipeline_request.build(),
                        ),
                    )
                    if not self.pipeline_request.is_connection_upgrade:
                        self.pipeline_request = None
            # For scenarios where we cannot peek into the data,
            # simply queue for upstream server.
            else:
                self.upstream.queue(raw)
            return None
        return raw

    def on_request_complete(self) -> Union[socket.socket, bool]:
        if not self.request.has_host():
            return False

        self.emit_request_complete()

        # Invoke plugin.before_upstream_connection
        #
        # before_upstream_connection can:
        # 1) Raise HttpRequestRejected exception to reject the connection
        # 2) return None to continue without establishing an upstream server connection
        #    e.g. for scenarios when plugins want to return response from cache, or,
        #    via out-of-band over the network request.
        do_connect = True
        for plugin in self.plugins.values():
            r = plugin.before_upstream_connection(self.request)
            if r is None:
                do_connect = False
                break
            self.request = r

        # Connect to upstream
        if do_connect:
            self.connect_upstream()

        # Invoke plugin.handle_client_request
        for plugin in self.plugins.values():
            assert self.request is not None
            r = plugin.handle_client_request(self.request)
            if r is not None:
                self.request = r
            else:
                return False

        # For https requests, respond back with tunnel established response.
        # Optionally, setup interceptor if TLS interception is enabled.
        if self.upstream:
            if self.request.is_https_tunnel:
                self.client.queue(
                    HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
                )
                if self.tls_interception_enabled():
                    return self.intercept()
            # If an upstream server connection was established for http request,
            # queue the request for upstream server.
            else:
                # - proxy-connection header is a mistake, it doesn't seem to be
                #   officially documented in any specification, drop it.
                # - proxy-authorization is of no use for upstream, remove it.
                self.request.del_headers(
                    [
                        httpHeaders.PROXY_AUTHORIZATION,
                        httpHeaders.PROXY_CONNECTION,
                    ],
                )
                # - For HTTP/1.0, connection header defaults to close
                # - For HTTP/1.1, connection header defaults to keep-alive
                # Respect headers sent by client instead of manipulating
                # Connection or Keep-Alive header.  However, note that per
                # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
                # connection headers are meant for communication between client and
                # first intercepting proxy.
                self.request.add_headers(
                    [(b'Via', b'1.1 %s' % PROXY_AGENT_HEADER_VALUE)],
                )
                # Disable args.disable_headers before dispatching to upstream
                self.upstream.queue(
                    memoryview(
                        self.request.build(
                            disable_headers=self.flags.disable_headers,
                        ),
                    ),
                )
        return False

    def handle_pipeline_response(self, raw: memoryview) -> None:
        if self.pipeline_response is None:
            self.pipeline_response = HttpParser(
                httpParserTypes.RESPONSE_PARSER,
            )
        # TODO(abhinavsingh): Remove .tobytes after parser is memoryview
        # compliant
        self.pipeline_response.parse(raw.tobytes())
        if self.pipeline_response.is_complete:
            self.pipeline_response = None

    def connect_upstream(self) -> None:
        host, port = self.request.host, self.request.port
        if host and port:
            if self.flags.enable_conn_pool:
                with self.lock:
                    created, self.upstream = self.pool.acquire(
                        text_(host), port,
                    )
            else:
                created, self.upstream = True, TcpServerConnection(
                    text_(host), port,
                )
            if not created:
                # NOTE: Acquired connection might be in an unusable state.
                #
                # This can only be confirmed by reading from connection.
                # For stale connections, we will receive None, indicating
                # to drop the connection.
                #
                # If that happen, we must acquire a fresh connection.
                logger.info(
                    'Reusing connection to upstream %s:%d' %
                    (text_(host), port),
                )
                return
            try:
                logger.debug(
                    'Connecting to upstream %s:%d' %
                    (text_(host), port),
                )
                # Invoke plugin.resolve_dns
                upstream_ip, source_addr = None, None
                for plugin in self.plugins.values():
                    upstream_ip, source_addr = plugin.resolve_dns(
                        text_(host), port,
                    )
                    if upstream_ip or source_addr:
                        break
                # Connect with overridden upstream IP and source address
                # if any of the plugin returned a non-null value.
                self.upstream.connect(
                    addr=None if not upstream_ip else (
                        upstream_ip, port,
                    ), source_address=source_addr,
                )
                self.upstream.connection.setblocking(False)
                logger.debug(
                    'Connected to upstream %s:%s' %
                    (text_(host), port),
                )
            except Exception as e:  # TimeoutError, socket.gaierror
                logger.warning(
                    'Unable to connect with upstream %s:%d due to %s' % (
                        text_(host), port, str(e),
                    ),
                )
                if self.flags.enable_conn_pool:
                    with self.lock:
                        self.pool.release(self.upstream)
                raise ProxyConnectionFailed(
                    text_(host), port, repr(e),
                ) from e
        else:
            logger.exception('Both host and port must exist')
            raise HttpProtocolException()

    #
    # Interceptor related methods
    #

    def gen_ca_signed_certificate(
            self, cert_file_path: str, certificate: Dict[str, Any],
    ) -> None:
        '''CA signing key (default) is used for generating a public key
        for common_name, if one already doesn't exist.  Using generated
        public key a CSR request is generated, which is then signed by
        CA key and secret.  Again this process only happen if signed
        certificate doesn't already exist.

        returns signed certificate path.'''
        assert(
            self.request.host and self.flags.ca_cert_dir and self.flags.ca_signing_key_file and
            self.flags.ca_key_file and self.flags.ca_cert_file
        )

        upstream_subject = {s[0][0]: s[0][1] for s in certificate['subject']}
        public_key_path = os.path.join(
            self.flags.ca_cert_dir,
            '{0}.{1}'.format(text_(self.request.host), 'pub'),
        )
        private_key_path = self.flags.ca_signing_key_file
        private_key_password = ''

        # Build certificate subject
        keys = {
            'CN': 'commonName',
            'C': 'countryName',
            'ST': 'stateOrProvinceName',
            'L': 'localityName',
            'O': 'organizationName',
            'OU': 'organizationalUnitName',
        }
        subject = ''
        for key in keys:
            if upstream_subject.get(keys[key], None):
                subject += '/{0}={1}'.format(
                    key,
                    upstream_subject.get(keys[key]),
                )
        alt_subj_names = [text_(self.request.host)]
        validity_in_days = 365 * 2
        timeout = 10

        # Generate a public key for the common name
        if not os.path.isfile(public_key_path):
            logger.debug('Generating public key %s', public_key_path)
            resp = gen_public_key(
                public_key_path=public_key_path, private_key_path=private_key_path,
                private_key_password=private_key_password, subject=subject, alt_subj_names=alt_subj_names,
                validity_in_days=validity_in_days, timeout=timeout,
            )
            assert(resp is True)

        csr_path = os.path.join(
            self.flags.ca_cert_dir,
            '{0}.{1}'.format(text_(self.request.host), 'csr'),
        )

        # Generate a CSR request for this common name
        if not os.path.isfile(csr_path):
            logger.debug('Generating CSR %s', csr_path)
            resp = gen_csr(
                csr_path=csr_path, key_path=private_key_path, password=private_key_password,
                crt_path=public_key_path, timeout=timeout,
            )
            assert(resp is True)

        ca_key_path = self.flags.ca_key_file
        ca_key_password = ''
        ca_crt_path = self.flags.ca_cert_file
        serial = '%d%d' % (time.time(), os.getpid())

        # Sign generated CSR
        if not os.path.isfile(cert_file_path):
            logger.debug('Signing CSR %s', cert_file_path)
            resp = sign_csr(
                csr_path=csr_path, crt_path=cert_file_path, ca_key_path=ca_key_path,
                ca_key_password=ca_key_password, ca_crt_path=ca_crt_path,
                serial=str(serial), alt_subj_names=alt_subj_names,
                validity_in_days=validity_in_days, timeout=timeout,
            )
            assert(resp is True)

    @staticmethod
    def generated_cert_file_path(ca_cert_dir: str, host: str) -> str:
        return os.path.join(ca_cert_dir, '%s.pem' % host)

    def generate_upstream_certificate(
            self, certificate: Dict[str, Any],
    ) -> str:
        if not (
            self.flags.ca_cert_dir and self.flags.ca_signing_key_file and
            self.flags.ca_cert_file and self.flags.ca_key_file
        ):
            raise HttpProtocolException(
                f'For certificate generation all the following flags are mandatory: '
                f'--ca-cert-file:{ self.flags.ca_cert_file }, '
                f'--ca-key-file:{ self.flags.ca_key_file }, '
                f'--ca-signing-key-file:{ self.flags.ca_signing_key_file }',
            )
        cert_file_path = HttpProxyPlugin.generated_cert_file_path(
            self.flags.ca_cert_dir, text_(self.request.host),
        )
        with self.lock:
            if not os.path.isfile(cert_file_path):
                self.gen_ca_signed_certificate(cert_file_path, certificate)
        return cert_file_path

    def intercept(self) -> Union[socket.socket, bool]:
        # Perform SSL/TLS handshake with upstream
        teardown = self.wrap_server()
        if teardown:
            return teardown
        # Generate certificate and perform handshake with client
        # wrap_client also flushes client data before wrapping
        # sending to client can raise, handle expected exceptions
        teardown = self.wrap_client()
        if teardown:
            return teardown
        # Update all plugin connection reference
        # TODO(abhinavsingh): Is this required?
        for plugin in self.plugins.values():
            plugin.client._conn = self.client.connection
        return self.client.connection

    def wrap_server(self) -> bool:
        assert self.upstream is not None
        assert isinstance(self.upstream.connection, socket.socket)
        do_close = False
        try:
            # check if has wrapped already
            logger.debug('type(self.upstream) = %s', type(self.upstream))
            if not isinstance(self.upstream.connection, ssl.SSLSocket):
                self.upstream.wrap(text_(self.request.host), self.flags.ca_file)
            else:
                logger.debug('self.upstream is ssl.SSLSocket already, do not need to wrap')
        except ssl.SSLCertVerificationError:    # Server raised certificate verification error
            # When --disable-interception-on-ssl-cert-verification-error flag is on,
            # we will cache such upstream hosts and avoid intercepting them for future
            # requests.
            logger.warning(
                'ssl.SSLCertVerificationError: ' +
                'Server raised cert verification error for upstream: {0}'.format(
                    self.upstream.addr[0],
                ),
            )
            do_close = True
        except ssl.SSLError as e:
            if e.reason == 'SSLV3_ALERT_HANDSHAKE_FAILURE':
                logger.warning(
                    '{0}: '.format(e.reason) +
                    'Server raised handshake alert failure for upstream: {0}'.format(
                        self.upstream.addr[0],
                    ),
                )
            else:
                logger.exception(
                    'SSLError when wrapping client for upstream: {0}'.format(
                        self.upstream.addr[0],
                    ), exc_info=e,
                )
            do_close = True
        if not do_close:
            assert isinstance(self.upstream.connection, ssl.SSLSocket)
        return do_close

    def wrap_client(self) -> bool:
        assert self.upstream is not None and self.flags.ca_signing_key_file is not None
        assert isinstance(self.upstream.connection, ssl.SSLSocket)
        do_close = False
        try:
            # TODO: Perform async certificate generation
            generated_cert = self.generate_upstream_certificate(
                cast(Dict[str, Any], self.upstream.connection.getpeercert()),
            )
            self.client.wrap(self.flags.ca_signing_key_file, generated_cert)
        except subprocess.TimeoutExpired as e:  # Popen communicate timeout
            logger.exception(
                'TimeoutExpired during certificate generation', exc_info=e,
            )
            do_close = True
        except ssl.SSLCertVerificationError:    # Client raised certificate verification error
            # When --disable-interception-on-ssl-cert-verification-error flag is on,
            # we will cache such upstream hosts and avoid intercepting them for future
            # requests.
            logger.warning(
                'ssl.SSLCertVerificationError: ' +
                'Client raised cert verification error for upstream: {0}'.format(
                    self.upstream.addr[0],
                ),
            )
            do_close = True
        except ssl.SSLEOFError as e:
            logger.warning(
                'ssl.SSLEOFError {0} when wrapping client for upstream: {1}'.format(
                    str(e), self.upstream.addr[0],
                ),
            )
            do_close = True
        except ssl.SSLError as e:
            if e.reason in ('TLSV1_ALERT_UNKNOWN_CA', 'UNSUPPORTED_PROTOCOL'):
                logger.warning(
                    '{0}: '.format(e.reason) +
                    'Client raised cert verification error for upstream: {0}'.format(
                        self.upstream.addr[0],
                    ),
                )
            else:
                logger.exception(
                    'OSError when wrapping client for upstream: {0}'.format(
                        self.upstream.addr[0],
                    ), exc_info=e,
                )
            do_close = True
        except BrokenPipeError:
            logger.error(
                'BrokenPipeError when wrapping client for upstream: {0}'.format(
                    self.upstream.addr[0],
                ),
            )
            do_close = True
        except OSError as e:
            logger.exception(
                'OSError when wrapping client for upstream: {0}'.format(
                    self.upstream.addr[0],
                ), exc_info=e,
            )
            do_close = True
        if not do_close:
            logger.debug('TLS intercepting using %s', generated_cert)
        return do_close

    #
    # Event emitter callbacks
    #

    def emit_request_complete(self) -> None:
        if not self.flags.enable_events:
            return
        assert self.request.port
        self.event_queue.publish(
            request_id=self.uid,
            event_name=eventNames.REQUEST_COMPLETE,
            event_payload={
                'url': text_(self.request.path)
                if self.request.is_https_tunnel
                else 'http://%s:%d%s' % (text_(self.request.host), self.request.port, text_(self.request.path)),
                'method': text_(self.request.method),
                'headers': {}
                if not self.request.headers else
                {
                    text_(k): text_(v[1])
                    for k, v in self.request.headers.items()
                },
                'body': text_(self.request.body)
                if self.request.method == httpMethods.POST
                else None,
            },
            publisher_id=self.__class__.__name__,
        )

    def emit_response_events(self, chunk_size: int) -> None:
        if not self.flags.enable_events:
            return
        if self.response.is_complete:
            self.emit_response_complete()
        elif self.response.state == httpParserStates.RCVING_BODY:
            self.emit_response_chunk_received(chunk_size)
        elif self.response.state == httpParserStates.HEADERS_COMPLETE:
            self.emit_response_headers_complete()

    def emit_response_headers_complete(self) -> None:
        if not self.flags.enable_events:
            return
        self.event_queue.publish(
            request_id=self.uid,
            event_name=eventNames.RESPONSE_HEADERS_COMPLETE,
            event_payload={
                'headers': {}
                if not self.response.headers else
                {
                    text_(k): text_(v[1])
                    for k, v in self.response.headers.items()
                },
            },
            publisher_id=self.__class__.__name__,
        )

    def emit_response_chunk_received(self, chunk_size: int) -> None:
        if not self.flags.enable_events:
            return
        self.event_queue.publish(
            request_id=self.uid,
            event_name=eventNames.RESPONSE_CHUNK_RECEIVED,
            event_payload={
                'chunk_size': chunk_size,
                'encoded_chunk_size': chunk_size,
            },
            publisher_id=self.__class__.__name__,
        )

    def emit_response_complete(self) -> None:
        if not self.flags.enable_events:
            return
        self.event_queue.publish(
            request_id=self.uid,
            event_name=eventNames.RESPONSE_COMPLETE,
            event_payload={
                'encoded_response_size': self.response.total_size,
            },
            publisher_id=self.__class__.__name__,
        )
