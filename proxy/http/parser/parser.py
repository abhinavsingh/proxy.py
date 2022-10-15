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
"""
import gzip
from typing import Dict, List, Type, Tuple, TypeVar, Optional

from ..url import Url
from .chunk import ChunkParser, chunkParserStates
from .types import httpParserTypes, httpParserStates
from ..methods import httpMethods
from .protocol import ProxyProtocol
from ..exception import HttpProtocolException
from ..protocols import httpProtocols
from ...common.flag import flags
from ...common.utils import (
    text_, bytes_, build_http_request, build_http_response,
)
from ...common.constants import (
    CRLF, COLON, SLASH, HTTP_1_0, HTTP_1_1, WHITESPACE, DEFAULT_HTTP_PORT,
    DEFAULT_DISABLE_HEADERS, DEFAULT_ENABLE_PROXY_PROTOCOL,
)


flags.add_argument(
    '--enable-proxy-protocol',
    action='store_true',
    default=DEFAULT_ENABLE_PROXY_PROTOCOL,
    help='Default: ' + str(DEFAULT_ENABLE_PROXY_PROTOCOL) + '.  ' +
    'If used, will enable proxy protocol.  ' +
    'Only version 1 is currently supported.',
)


T = TypeVar('T', bound='HttpParser')


class HttpParser:
    """HTTP request/response parser.

    TODO: Make me zero-copy by using :class:`memoryview`.
    Currently due to chunk/buffer handling we
    are not able to utilize :class:`memoryview`
    efficiently.

    For this to happen we must store ``buffer``
    as ``List[memoryview]`` instead of raw bytes and
    update parser to work accordingly.
    """

    def __init__(
            self, parser_type: int,
            enable_proxy_protocol: int = DEFAULT_ENABLE_PROXY_PROTOCOL,
    ) -> None:
        self.state: int = httpParserStates.INITIALIZED
        self.type: int = parser_type
        self.protocol: Optional[ProxyProtocol] = None
        if enable_proxy_protocol:
            assert self.type == httpParserTypes.REQUEST_PARSER
            self.protocol = ProxyProtocol()
        # Request attributes
        self.host: Optional[bytes] = None
        self.port: Optional[int] = None
        self.path: Optional[bytes] = None
        self.method: Optional[bytes] = None
        # Response attributes
        self.code: Optional[bytes] = None
        self.reason: Optional[bytes] = None
        self.version: Optional[bytes] = None
        # Total size of raw bytes passed for parsing
        self.total_size: int = 0
        # Buffer to hold unprocessed bytes
        self.buffer: Optional[memoryview] = None
        # Internal headers data structure:
        # - Keys are lower case header names.
        # - Values are 2-tuple containing original
        #   header and it's value as received.
        self.headers: Optional[Dict[bytes, Tuple[bytes, bytes]]] = None
        self.body: Optional[bytes] = None
        self.chunk: Optional[ChunkParser] = None
        # Internal request line as a url structure
        self._url: Optional[Url] = None
        # Deduced states from the packet
        self._is_chunked_encoded: bool = False
        self._content_expected: bool = False
        self._is_https_tunnel: bool = False

    @classmethod
    def request(
            cls: Type[T],
            raw: bytes,
            enable_proxy_protocol: int = DEFAULT_ENABLE_PROXY_PROTOCOL,
    ) -> T:
        parser = cls(
            httpParserTypes.REQUEST_PARSER,
            enable_proxy_protocol=enable_proxy_protocol,
        )
        parser.parse(memoryview(raw))
        return parser

    @classmethod
    def response(cls: Type[T], raw: bytes) -> T:
        parser = cls(httpParserTypes.RESPONSE_PARSER)
        parser.parse(memoryview(raw))
        return parser

    def header(self, key: bytes) -> bytes:
        """Convenient method to return original header value from internal data structure."""
        if self.headers is None or key.lower() not in self.headers:
            raise KeyError('%s not found in headers' % text_(key))
        return self.headers[key.lower()][1]

    def has_header(self, key: bytes) -> bool:
        """Returns true if header key was found in payload."""
        if self.headers is None:
            return False
        return key.lower() in self.headers

    def add_header(self, key: bytes, value: bytes) -> bytes:
        """Add/Update a header to internal data structure.

        Returns key with which passed (key, value) tuple is available."""
        if self.headers is None:
            self.headers = {}
        k = key.lower()
        # k = key
        self.headers[k] = (key, value)
        return k

    def add_headers(self, headers: List[Tuple[bytes, bytes]]) -> None:
        """Add/Update multiple headers to internal data structure"""
        for (key, value) in headers:
            self.add_header(key, value)

    def del_header(self, header: bytes) -> None:
        """Delete a header from internal data structure."""
        if self.headers and header.lower() in self.headers:
            del self.headers[header.lower()]

    def del_headers(self, headers: List[bytes]) -> None:
        """Delete headers from internal data structure."""
        for key in headers:
            self.del_header(key.lower())

    def set_url(self, url: bytes, allowed_url_schemes: Optional[List[bytes]] = None) -> None:
        """Given a request line, parses it and sets line attributes a.k.a. host, port, path."""
        self._url = Url.from_bytes(
            url, allowed_url_schemes=allowed_url_schemes,
        )
        self._set_line_attributes()

    def update_body(self, body: bytes, content_type: bytes) -> None:
        """This method must be used to update body after HTTP packet has been parsed.

        Along with updating the body, this method also respects original
        request content encoding, transfer encoding settings."""
        # If outgoing request encoding is gzip
        # also compress the body
        if self.has_header(b'content-encoding'):
            if self.header(b'content-encoding') == b'gzip':
                body = gzip.compress(body)
            else:
                # We only work with gzip, for any other encoding
                # type, remove the original header
                self.del_header(b'content-encoding')
        # If the request is of type chunked encoding
        # add post data as chunk
        if self.is_chunked_encoded:
            body = ChunkParser.to_chunks(body)
            self.del_header(b'content-length')
        else:
            self.add_header(
                b'Content-Length',
                bytes_(len(body)),
            )
        self.body = body
        self.add_header(b'Content-Type', content_type)

    @property
    def http_handler_protocol(self) -> int:
        """Returns `HttpProtocols` that this request belongs to."""
        if self.version in (HTTP_1_1, HTTP_1_0) and self._url is not None:
            if self.host is not None:
                return httpProtocols.HTTP_PROXY
            if self._url.hostname is None:
                return httpProtocols.WEB_SERVER
        return httpProtocols.UNKNOWN

    @property
    def is_complete(self) -> bool:
        return self.state == httpParserStates.COMPLETE

    @property
    def is_http_1_1_keep_alive(self) -> bool:
        """Returns true for HTTP/1.1 keep-alive connections."""
        return self.version == HTTP_1_1 and \
            (
                not self.has_header(b'Connection') or
                self.header(b'Connection').lower() == b'keep-alive'
            )

    @property
    def is_connection_upgrade(self) -> bool:
        """Returns true for websocket upgrade requests."""
        return self.version == HTTP_1_1 and \
            self.has_header(b'Connection') and \
            self.has_header(b'Upgrade')

    @property
    def is_https_tunnel(self) -> bool:
        """Returns true for HTTPS CONNECT tunnel request."""
        return self._is_https_tunnel

    @property
    def is_chunked_encoded(self) -> bool:
        """Returns true if transfer-encoding chunked is used."""
        return self._is_chunked_encoded

    @property
    def content_expected(self) -> bool:
        """Returns true if content-length is present and not 0."""
        return self._content_expected

    @property
    def body_expected(self) -> bool:
        """Returns true if content or chunked response is expected."""
        return self._content_expected or self._is_chunked_encoded

    def parse(
            self,
            raw: memoryview,
            allowed_url_schemes: Optional[List[bytes]] = None,
    ) -> None:
        """Parses HTTP request out of raw bytes.

        Check for `HttpParser.state` after `parse` has successfully returned."""
        size = len(raw)
        self.total_size += size
        if self.buffer:
            # TODO(abhinavsingh): Instead of tobytes our parser
            # must be capable of working with arrays of memoryview
            raw = memoryview(self.buffer.tobytes() + raw.tobytes())
        self.buffer, more = None, size > 0
        while more and self.state != httpParserStates.COMPLETE:
            # gte with HEADERS_COMPLETE also encapsulated RCVING_BODY state
            if self.state >= httpParserStates.HEADERS_COMPLETE:
                more, raw = self._process_body(raw)
            elif self.state == httpParserStates.INITIALIZED:
                more, raw = self._process_line(
                    raw,
                    allowed_url_schemes=allowed_url_schemes,
                )
            else:
                more, raw = self._process_headers(raw)
            # When server sends a response line without any header or body e.g.
            # HTTP/1.1 200 Connection established\r\n\r\n
            if self.type == httpParserTypes.RESPONSE_PARSER and \
                    self.state == httpParserStates.LINE_RCVD and \
                    raw == CRLF:
                self.state = httpParserStates.COMPLETE
            # Mark request as complete if headers received and no incoming
            # body indication received.
            elif self.state == httpParserStates.HEADERS_COMPLETE and \
                    not (self._content_expected or self._is_chunked_encoded) and \
                    raw == b'':
                self.state = httpParserStates.COMPLETE
        self.buffer = None if raw == b'' else raw

    def build(self, disable_headers: Optional[List[bytes]] = None, for_proxy: bool = False) -> bytes:
        """Rebuild the request object."""
        assert self.method and self.version and self.type == httpParserTypes.REQUEST_PARSER
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS
        body: Optional[bytes] = self._get_body_or_chunks()
        path = self.path or b'/'
        if for_proxy:
            assert self.host and self.port and self._url
            path = (
                b'http' if not self._url.scheme else self._url.scheme +
                COLON + SLASH + SLASH +
                self.host +
                COLON +
                str(self.port).encode() +
                path
            ) if not self._is_https_tunnel else (self.host + COLON + str(self.port).encode())
        return build_http_request(
            self.method, path, self.version,
            headers={} if not self.headers else {
                self.headers[k][0]: self.headers[k][1] for k in self.headers if
                k.lower() not in disable_headers
            },
            body=body,
            no_ua=True,
        )

    def build_response(self) -> bytes:
        """Rebuild the response object."""
        assert self.code and self.version and self.type == httpParserTypes.RESPONSE_PARSER
        return build_http_response(
            status_code=int(self.code),
            protocol_version=self.version,
            reason=self.reason,
            headers={} if not self.headers else {
                self.headers[k][0]: self.headers[k][1] for k in self.headers
            },
            body=self._get_body_or_chunks(),
        )

    def _process_body(self, raw: memoryview) -> Tuple[bool, memoryview]:
        # Ref: http://www.ietf.org/rfc/rfc2616.txt
        # 3.If a Content-Length header field (section 14.13) is present, its
        #   decimal value in OCTETs represents both the entity-length and the
        #   transfer-length. The Content-Length header field MUST NOT be sent
        #   if these two lengths are different (i.e., if a Transfer-Encoding
        #   header field is present). If a message is received with both a
        #   Transfer-Encoding header field and a Content-Length header field,
        #   the latter MUST be ignored.
        #
        # TL;DR -- Give transfer-encoding header preference over content-length.
        if self._is_chunked_encoded:
            if not self.chunk:
                self.chunk = ChunkParser()
            raw = self.chunk.parse(raw)
            if self.chunk.state == chunkParserStates.COMPLETE:
                self.body = self.chunk.body
                self.state = httpParserStates.COMPLETE
            more = False
            return more, raw
        if self._content_expected:
            self.state = httpParserStates.RCVING_BODY
            if self.body is None:
                self.body = b''
            total_size = int(self.header(b'content-length'))
            received_size = len(self.body)
            self.body += raw[:total_size - received_size]
            if self.body and \
                    len(self.body) == int(self.header(b'content-length')):
                self.state = httpParserStates.COMPLETE
            return len(raw) > 0, raw[total_size - received_size:]
        # Received a packet without content-length header
        # and no transfer-encoding specified.
        #
        # This can happen for both HTTP/1.0 and HTTP/1.1 scenarios.
        # Currently, we consume the remaining buffer as body.
        #
        # Ref https://github.com/abhinavsingh/proxy.py/issues/398
        #
        # See TestHttpParser.test_issue_398 scenario
        self.state = httpParserStates.RCVING_BODY
        self.body = bytes(raw)
        return False, memoryview(b'')

    def _process_headers(self, raw: memoryview) -> Tuple[bool, memoryview]:
        """Returns False when no CRLF could be found in received bytes.

        TODO: We should not return until parser reaches headers complete
        state or when there is no more data left to parse.

        TODO: For protection against Slowloris attack, we must parse the
        request line and headers only after receiving end of header marker.
        This will also help make the parser even more stateless.
        """
        while True:
            parts = raw.tobytes().split(CRLF, 1)
            if len(parts) == 1:
                return False, raw
            line, raw = parts[0], memoryview(parts[1])
            if self.state in (httpParserStates.LINE_RCVD, httpParserStates.RCVING_HEADERS):
                if line == b'' or line.strip() == b'':  # Blank line received.
                    self.state = httpParserStates.HEADERS_COMPLETE
                else:
                    self.state = httpParserStates.RCVING_HEADERS
                    self._process_header(line)
            # If raw length is now zero, bail out
            # If we have received all headers, bail out
            if raw == b'' or self.state == httpParserStates.HEADERS_COMPLETE:
                break
        return len(raw) > 0, raw

    def _process_line(
            self,
            raw: memoryview,
            allowed_url_schemes: Optional[List[bytes]] = None,
    ) -> Tuple[bool, memoryview]:
        while True:
            parts = raw.tobytes().split(CRLF, 1)
            if len(parts) == 1:
                return False, raw
            line, raw = parts[0], memoryview(parts[1])
            if self.type == httpParserTypes.REQUEST_PARSER:
                if self.protocol is not None and self.protocol.version is None:
                    # We expect to receive entire proxy protocol v1 line
                    # in one network read and don't expect partial packets
                    self.protocol.parse(line)
                    continue
                # Ref: https://datatracker.ietf.org/doc/html/rfc2616#section-5.1
                parts = line.split(WHITESPACE, 2)
                if len(parts) == 3:
                    self.method = parts[0]
                    if self.method == httpMethods.CONNECT:
                        self._is_https_tunnel = True
                    self.set_url(
                        parts[1], allowed_url_schemes=allowed_url_schemes,
                    )
                    self.version = parts[2]
                    self.state = httpParserStates.LINE_RCVD
                    break
                # To avoid a possible attack vector, we raise exception
                # if parser receives an invalid request line.
                raise HttpProtocolException('Invalid request line %r' % raw)
            parts = line.split(WHITESPACE, 2)
            self.version = parts[0]
            self.code = parts[1]
            # Our own WebServerPlugin example currently doesn't send any reason
            if len(parts) == 3:
                self.reason = parts[2]
            self.state = httpParserStates.LINE_RCVD
            break
        return len(raw) > 0, raw

    def _process_header(self, raw: bytes) -> None:
        parts = raw.split(COLON, 1)
        key, value = (
            parts[0].strip(),
            b'' if len(parts) == 1 else parts[1].strip(),
        )
        k = self.add_header(key, value)
        # b'content-length' in self.headers and int(self.header(b'content-length')) > 0
        if k == b'content-length' and int(value) > 0:
            self._content_expected = True
        # return b'transfer-encoding' in self.headers and \
        #   self.headers[b'transfer-encoding'][1].lower() == b'chunked'
        elif k == b'transfer-encoding' and value.lower() == b'chunked':
            self._is_chunked_encoded = True

    def _get_body_or_chunks(self) -> Optional[bytes]:
        return ChunkParser.to_chunks(self.body) \
            if self.body and self._is_chunked_encoded else \
            self.body

    def _set_line_attributes(self) -> None:
        if self.type == httpParserTypes.REQUEST_PARSER:
            assert self._url
            if self._is_https_tunnel:
                self.host = self._url.hostname
                self.port = 443 if self._url.port is None else self._url.port
            else:
                self.host, self.port = self._url.hostname, self._url.port \
                    if self._url.port else DEFAULT_HTTP_PORT
            self.path = self._url.remainder
