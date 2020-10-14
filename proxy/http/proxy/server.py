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
import threading
import subprocess
import os
import ssl
import socket
import time
import errno
from typing import Optional, List, Union, Dict, cast, Any, Tuple

from .plugin import HttpProxyBasePlugin
from ..plugin import HttpProtocolHandlerPlugin
from ..exception import HttpProtocolException, ProxyConnectionFailed
from ..codes import httpStatusCodes
from ..parser import HttpParser, httpParserStates, httpParserTypes
from ..methods import httpMethods

from ...common.types import Readables, Writables
from ...common.constants import COMMA, DEFAULT_CA_CERT_DIR, DEFAULT_CA_CERT_FILE, DEFAULT_CA_FILE, DEFAULT_SERVER_RECVBUF_SIZE
from ...common.constants import DEFAULT_CA_KEY_FILE, DEFAULT_CA_SIGNING_KEY_FILE, DEFAULT_CERT_FILE
from ...common.constants import PROXY_AGENT_HEADER_VALUE, DEFAULT_DISABLE_HEADERS
from ...common.utils import build_http_response, text_
from ...common.pki import gen_public_key, gen_csr, sign_csr

from ...core.event import eventNames
from ...core.connection import TcpServerConnection, TcpConnectionUninitializedException
from ...common.flag import flags

logger = logging.getLogger(__name__)


flags.add_argument(
    '--ca-key-file',
    type=str,
    default=DEFAULT_CA_KEY_FILE,
    help='Default: None. CA key to use for signing dynamically generated '
    'HTTPS certificates.  If used, must also pass --ca-cert-file and --ca-signing-key-file'
)
flags.add_argument(
    '--ca-cert-dir',
    type=str,
    default=DEFAULT_CA_CERT_DIR,
    help='Default: ~/.proxy.py. Directory to store dynamically generated certificates. '
    'Also see --ca-key-file, --ca-cert-file and --ca-signing-key-file'
)
flags.add_argument(
    '--ca-cert-file',
    type=str,
    default=DEFAULT_CA_CERT_FILE,
    help='Default: None. Signing certificate to use for signing dynamically generated '
    'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-signing-key-file'
)
flags.add_argument(
    '--ca-file',
    type=str,
    default=DEFAULT_CA_FILE,
    help='Default: None. Provide path to custom CA file for peer certificate validation. '
    'Specially useful on MacOS.'
)
flags.add_argument(
    '--ca-signing-key-file',
    type=str,
    default=DEFAULT_CA_SIGNING_KEY_FILE,
    help='Default: None. CA signing key to use for dynamic generation of '
    'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-cert-file'
)
flags.add_argument(
    '--cert-file',
    type=str,
    default=DEFAULT_CERT_FILE,
    help='Default: None. Server certificate to enable end-to-end TLS encryption with clients. '
    'If used, must also pass --key-file.'
)
flags.add_argument(
    '--disable-headers',
    type=str,
    default=COMMA.join(DEFAULT_DISABLE_HEADERS),
    help='Default: None.  Comma separated list of headers to remove before '
    'dispatching client request to upstream server.')
flags.add_argument(
    '--server-recvbuf-size',
    type=int,
    default=DEFAULT_SERVER_RECVBUF_SIZE,
    help='Default: 1 MB. Maximum amount of data received from the '
    'server in a single recv() operation. Bump this '
    'value for faster downloads at the expense of '
    'increased RAM.')


class HttpProxyPlugin(HttpProtocolHandlerPlugin):
    """HttpProtocolHandler plugin which implements HttpProxy specifications."""

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = memoryview(build_http_response(
        httpStatusCodes.OK,
        reason=b'Connection established'
    ))

    # Used to synchronization during certificate generation.
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

    def tls_interception_enabled(self) -> bool:
        return self.flags.ca_key_file is not None and \
            self.flags.ca_cert_dir is not None and \
            self.flags.ca_signing_key_file is not None and \
            self.flags.ca_cert_file is not None

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

    def write_to_descriptors(self, w: Writables) -> bool:
        if self.request.has_upstream_server() and \
                self.server and not self.server.closed and \
                self.server.has_buffer() and \
                self.server.connection in w:
            logger.debug('Server is write ready, flushing buffer')
            try:
                self.server.flush()
            except ssl.SSLWantWriteError:
                logger.warning(
                    'SSLWantWriteError while trying to flush to server, will retry')
                return False
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for server')
                return True
            except OSError as e:
                logger.exception(
                    'OSError when flushing buffer to server', exc_info=e)
                return True
        return False

    def read_from_descriptors(self, r: Readables) -> bool:
        if self.request.has_upstream_server(
        ) and self.server and not self.server.closed and self.server.connection in r:
            logger.debug('Server is ready for reads, reading...')
            try:
                raw = self.server.recv(self.flags.server_recvbuf_size)
            except TimeoutError as e:
                if e.errno == errno.ETIMEDOUT:
                    logger.warning(
                        '%s:%d timed out on recv' %
                        self.server.addr)
                    return True
                else:
                    raise e
            except ssl.SSLWantReadError:    # Try again later
                # logger.warning('SSLWantReadError encountered while reading from server, will retry ...')
                return False
            except OSError as e:
                if e.errno == errno.EHOSTUNREACH:
                    logger.warning(
                        '%s:%d unreachable on recv' %
                        self.server.addr)
                    return True
                elif e.errno == errno.ECONNRESET:
                    logger.warning('Connection reset by upstream: %r' % e)
                else:
                    logger.exception(
                        'Exception while receiving from %s connection %r with reason %r' %
                        (self.server.tag, self.server.connection, e))
                return True

            if raw is None:
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
                # or self.tls_interception_enabled():
                if self.response.state == httpParserStates.COMPLETE:
                    self.handle_pipeline_response(raw)
                else:
                    # TODO(abhinavsingh): Remove .tobytes after parser is
                    # memoryview compliant
                    self.response.parse(raw.tobytes())
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
                'Closed server connection, has buffer %s' %
                self.server.has_buffer())

    def on_response_chunk(self, chunk: List[memoryview]) -> List[memoryview]:
        # TODO: Allow to output multiple access_log lines
        # for each request over a pipelined HTTP connection (not for HTTPS).
        # However, this must also be accompanied by resetting both request
        # and response objects.
        #
        # if not self.request.method == httpMethods.CONNECT and \
        #         self.response.state == httpParserStates.COMPLETE:
        #     self.access_log()
        return chunk

    def on_client_data(self, raw: memoryview) -> Optional[memoryview]:
        if not self.request.has_upstream_server():
            return raw

        if self.server and not self.server.closed:
            if self.request.state == httpParserStates.COMPLETE and (
                    self.request.method != httpMethods.CONNECT or
                    self.tls_interception_enabled()):
                if self.pipeline_request is not None and \
                        self.pipeline_request.is_connection_upgrade():
                    # Previous pipelined request was a WebSocket
                    # upgrade request. Incoming client data now
                    # must be treated as WebSocket protocol packets.
                    self.server.queue(raw)
                    return None

                if self.pipeline_request is None:
                    self.pipeline_request = HttpParser(
                        httpParserTypes.REQUEST_PARSER)

                # TODO(abhinavsingh): Remove .tobytes after parser is
                # memoryview compliant
                self.pipeline_request.parse(raw.tobytes())
                if self.pipeline_request.state == httpParserStates.COMPLETE:
                    for plugin in self.plugins.values():
                        assert self.pipeline_request is not None
                        r = plugin.handle_client_request(self.pipeline_request)
                        if r is None:
                            return None
                        self.pipeline_request = r
                    assert self.pipeline_request is not None
                    # TODO(abhinavsingh): Remove memoryview wrapping here after
                    # parser is fully memoryview compliant
                    self.server.queue(
                        memoryview(
                            self.pipeline_request.build()))
                    if not self.pipeline_request.is_connection_upgrade():
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
            if self.tls_interception_enabled():
                # Perform SSL/TLS handshake with upstream
                self.wrap_server()
                # Generate certificate and perform handshake with client
                try:
                    # wrap_client also flushes client data before wrapping
                    # sending to client can raise, handle expected exceptions
                    self.wrap_client()
                except subprocess.TimeoutExpired as e:  # Popen communicate timeout
                    logger.exception(
                        'TimeoutExpired during certificate generation', exc_info=e)
                    return True
                except BrokenPipeError:
                    logger.error(
                        'BrokenPipeError when wrapping client')
                    return True
                except OSError as e:
                    logger.exception(
                        'OSError when wrapping client', exc_info=e)
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
                memoryview(self.request.build(
                    disable_headers=self.flags.disable_headers)))
        return False

    def handle_pipeline_response(self, raw: memoryview) -> None:
        if self.pipeline_response is None:
            self.pipeline_response = HttpParser(
                httpParserTypes.RESPONSE_PARSER)
        # TODO(abhinavsingh): Remove .tobytes after parser is memoryview
        # compliant
        self.pipeline_response.parse(raw.tobytes())
        if self.pipeline_response.state == httpParserStates.COMPLETE:
            self.pipeline_response = None

    def access_log(self) -> None:
        server_host, server_port = self.server.addr if self.server else (
            None, None)
        connection_time_ms = (time.time() - self.start_time) * 1000
        if self.request.method == httpMethods.CONNECT:
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

    def gen_ca_signed_certificate(
            self, cert_file_path: str, certificate: Dict[str, Any]) -> None:
        '''CA signing key (default) is used for generating a public key
        for common_name, if one already doesn't exist.  Using generated
        public key a CSR request is generated, which is then signed by
        CA key and secret.  Again this process only happen if signed
        certificate doesn't already exist.

        returns signed certificate path.'''
        assert(self.request.host and self.flags.ca_cert_dir and self.flags.ca_signing_key_file and
               self.flags.ca_key_file and self.flags.ca_cert_file)

        upstream_subject = {s[0][0]: s[0][1] for s in certificate['subject']}
        public_key_path = os.path.join(self.flags.ca_cert_dir,
                                       '{0}.{1}'.format(text_(self.request.host), 'pub'))
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
                subject += '/{0}={1}'.format(key,
                                             upstream_subject.get(keys[key]))
        alt_subj_names = [text_(self.request.host), ]
        validity_in_days = 365 * 2
        timeout = 10

        # Generate a public key for the common name
        if not os.path.isfile(public_key_path):
            logger.debug('Generating public key %s', public_key_path)
            resp = gen_public_key(public_key_path=public_key_path, private_key_path=private_key_path,
                                  private_key_password=private_key_password, subject=subject, alt_subj_names=alt_subj_names,
                                  validity_in_days=validity_in_days, timeout=timeout)
            assert(resp is True)

        csr_path = os.path.join(self.flags.ca_cert_dir,
                                '{0}.{1}'.format(text_(self.request.host), 'csr'))

        # Generate a CSR request for this common name
        if not os.path.isfile(csr_path):
            logger.debug('Generating CSR %s', csr_path)
            resp = gen_csr(csr_path=csr_path, key_path=private_key_path, password=private_key_password,
                           crt_path=public_key_path, timeout=timeout)
            assert(resp is True)

        ca_key_path = self.flags.ca_key_file
        ca_key_password = ''
        ca_crt_path = self.flags.ca_cert_file
        serial = self.uid.int

        # Sign generated CSR
        if not os.path.isfile(cert_file_path):
            logger.debug('Signing CSR %s', cert_file_path)
            resp = sign_csr(csr_path=csr_path, crt_path=cert_file_path, ca_key_path=ca_key_path,
                            ca_key_password=ca_key_password, ca_crt_path=ca_crt_path,
                            serial=str(serial), alt_subj_names=alt_subj_names,
                            validity_in_days=validity_in_days, timeout=timeout)
            assert(resp is True)

    @staticmethod
    def generated_cert_file_path(ca_cert_dir: str, host: str) -> str:
        return os.path.join(ca_cert_dir, '%s.pem' % host)

    def generate_upstream_certificate(
            self, certificate: Dict[str, Any]) -> str:
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
                self.gen_ca_signed_certificate(cert_file_path, certificate)
        return cert_file_path

    def wrap_server(self) -> None:
        assert self.server is not None
        assert isinstance(self.server.connection, socket.socket)
        self.server.wrap(text_(self.request.host), self.flags.ca_file)
        assert isinstance(self.server.connection, ssl.SSLSocket)

    def wrap_client(self) -> None:
        assert self.server is not None and self.flags.ca_signing_key_file is not None
        assert isinstance(self.server.connection, ssl.SSLSocket)
        generated_cert = self.generate_upstream_certificate(
            cast(Dict[str, Any], self.server.connection.getpeercert()))
        self.client.wrap(self.flags.ca_signing_key_file, generated_cert)
        logger.debug(
            'TLS interception using %s', generated_cert)

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
            request_id=self.uid.hex,
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
