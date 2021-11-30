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
from typing import TypeVar, Optional, Dict, Type, Tuple, List

from ...common.constants import DEFAULT_DISABLE_HEADERS, COLON, DEFAULT_ENABLE_PROXY_PROTOCOL
from ...common.constants import HTTP_1_1, HTTP_1_0, SLASH, CRLF
from ...common.constants import WHITESPACE, DEFAULT_HTTP_PORT
from ...common.utils import build_http_request, build_http_response, find_http_line, text_
from ...common.flag import flags
from ...common.backports import cached_property

from ..url import Url
from ..methods import httpMethods

from .protocol import ProxyProtocol
from .chunk import ChunkParser, chunkParserStates
from .types import httpParserTypes, httpParserStates

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
        self.host: Optional[bytes] = None
        self.port: Optional[int] = None
        self.path: Optional[bytes] = None
        self.method: Optional[bytes] = None
        self.code: Optional[bytes] = None
        self.reason: Optional[bytes] = None
        self.version: Optional[bytes] = None
        # Total size of raw bytes passed for parsing
        self.total_size: int = 0
        # Buffer to hold unprocessed bytes
        self.buffer: bytes = b''
        # Internal headers datastructure:
        # - Keys are lower case header names.
        # - Values are 2-tuple containing original
        #   header and it's value as received.
        self.headers: Dict[bytes, Tuple[bytes, bytes]] = {}
        self.body: Optional[bytes] = None
        self.chunk: Optional[ChunkParser] = None
        # Internal request line as a url structure
        self._url: Optional[Url] = None

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
        parser.parse(raw)
        return parser

    @classmethod
    def response(cls: Type[T], raw: bytes) -> T:
        parser = cls(httpParserTypes.RESPONSE_PARSER)
        parser.parse(raw)
        return parser

    def header(self, key: bytes) -> bytes:
        """Convenient method to return original header value from internal data structure."""
        if key.lower() not in self.headers:
            raise KeyError('%s not found in headers', text_(key))
        return self.headers[key.lower()][1]

    def has_header(self, key: bytes) -> bool:
        """Returns true if header key was found in payload."""
        return key.lower() in self.headers

    def add_header(self, key: bytes, value: bytes) -> None:
        """Add/Update a header to internal data structure."""
        self.headers[key.lower()] = (key, value)

    def add_headers(self, headers: List[Tuple[bytes, bytes]]) -> None:
        """Add/Update multiple headers to internal data structure"""
        for (key, value) in headers:
            self.add_header(key, value)

    def del_header(self, header: bytes) -> None:
        """Delete a header from internal data structure."""
        if header.lower() in self.headers:
            del self.headers[header.lower()]

    def del_headers(self, headers: List[bytes]) -> None:
        """Delete headers from internal data structure."""
        for key in headers:
            self.del_header(key.lower())

    def set_url(self, url: bytes) -> None:
        """Given a request line, parses it and sets line attributes a.k.a. host, port, path."""
        self._url = Url.from_bytes(url)
        self._set_line_attributes()

    def has_host(self) -> bool:
        """Returns whether host line attribute was parsed or set.

        NOTE: Host field WILL be None for incoming local WebServer requests."""
        return self.host is not None

    @cached_property(ttl=0)
    def is_http_1_1_keep_alive(self) -> bool:
        """Returns true for HTTP/1.1 keep-alive connections."""
        return self.version == HTTP_1_1 and \
            (
                not self.has_header(b'Connection') or
                self.header(b'Connection').lower() == b'keep-alive'
            )

    @cached_property(ttl=0)
    def is_connection_upgrade(self) -> bool:
        """Returns true for websocket upgrade requests."""
        return self.version == HTTP_1_1 and \
            self.has_header(b'Connection') and \
            self.has_header(b'Upgrade')

    @cached_property(ttl=0)
    def is_https_tunnel(self) -> bool:
        """Returns true for HTTPS CONNECT tunnel request."""
        return self.method == httpMethods.CONNECT

    @cached_property(ttl=0)
    def is_chunked_encoded(self) -> bool:
        """Returns true if transfer-encoding chunked is used."""
        return b'transfer-encoding' in self.headers and \
               self.headers[b'transfer-encoding'][1].lower() == b'chunked'

    @cached_property(ttl=0)
    def content_expected(self) -> bool:
        """Returns true if content-length is present and not 0."""
        return b'content-length' in self.headers and int(self.header(b'content-length')) > 0

    @cached_property(ttl=0)
    def body_expected(self) -> bool:
        """Returns true if content or chunked response is expected."""
        return self.content_expected or self.is_chunked_encoded     # type: ignore[no-any-return]

    def parse(self, raw: bytes) -> None:
        """Parses HTTP request out of raw bytes.

        Check for `HttpParser.state` after `parse` has successfully returned."""
        self.total_size += len(raw)
        raw = self.buffer + raw
        self.buffer, more = b'', len(raw) > 0
        while more and self.state != httpParserStates.COMPLETE:
            # gte with HEADERS_COMPLETE also encapsulated RCVING_BODY state
            more, raw = self._process_body(raw) \
                if self.state >= httpParserStates.HEADERS_COMPLETE else \
                self._process_line_and_headers(raw)
        self.buffer = raw

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
            ) if not self.is_https_tunnel else (self.host + COLON + str(self.port).encode())
        return build_http_request(
            self.method, path, self.version,
            headers={} if not self.headers else {
                self.headers[k][0]: self.headers[k][1] for k in self.headers if
                k.lower() not in disable_headers
            },
            body=body,
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

    def _process_body(self, raw: bytes) -> Tuple[bool, bytes]:
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
        if self.is_chunked_encoded:
            if not self.chunk:
                self.chunk = ChunkParser()
            raw = self.chunk.parse(raw)
            if self.chunk.state == chunkParserStates.COMPLETE:
                self.body = self.chunk.body
                self.state = httpParserStates.COMPLETE
            more = False
        elif b'content-length' in self.headers:
            self.state = httpParserStates.RCVING_BODY
            if self.body is None:
                self.body = b''
            total_size = int(self.header(b'content-length'))
            received_size = len(self.body)
            self.body += raw[:total_size - received_size]
            if self.body and \
                    len(self.body) == int(self.header(b'content-length')):
                self.state = httpParserStates.COMPLETE
            more, raw = len(raw) > 0, raw[total_size - received_size:]
        else:
            # HTTP/1.0 scenario only
            assert self.version == HTTP_1_0
            self.state = httpParserStates.RCVING_BODY
            # Received a packet without content-length header
            # and no transfer-encoding specified.
            #
            # Ref https://github.com/abhinavsingh/proxy.py/issues/398
            # See TestHttpParser.test_issue_398 scenario
            self.body = raw
            more, raw = False, b''
        return more, raw

    def _process_line_and_headers(self, raw: bytes) -> Tuple[bool, bytes]:
        """Returns False when no CRLF could be found in received bytes.

        TODO: We should not return until parser reaches headers complete
        state or when there is no more data left to parse.

        TODO: For protection against Slowloris attack, we must parse the
        request line and headers only after receiving end of header marker.
        This will also help make the parser even more stateless.
        """
        while True:
            line, raw = find_http_line(raw)
            if line is None:
                return False, raw

            if self.state == httpParserStates.INITIALIZED:
                self._process_line(line)
                if self.state == httpParserStates.INITIALIZED:
                    # return len(raw) > 0, raw
                    continue
            elif self.state in (httpParserStates.LINE_RCVD, httpParserStates.RCVING_HEADERS):
                if self.state == httpParserStates.LINE_RCVD:
                    self.state = httpParserStates.RCVING_HEADERS
                if line == b'' or line.strip() == b'':  # Blank line received.
                    self.state = httpParserStates.HEADERS_COMPLETE
                else:
                    self._process_header(line)

            # When server sends a response line without any header or body e.g.
            # HTTP/1.1 200 Connection established\r\n\r\n
            if self.state == httpParserStates.LINE_RCVD and \
                    self.type == httpParserTypes.RESPONSE_PARSER and \
                    raw == CRLF:
                self.state = httpParserStates.COMPLETE
            elif self.state == httpParserStates.HEADERS_COMPLETE and \
                    not self.body_expected and \
                    raw == b'':
                self.state = httpParserStates.COMPLETE

            # If raw length is now zero, bail out
            # If we have received all headers, bail out
            if raw == b'' or self.state == httpParserStates.HEADERS_COMPLETE:
                break
        return len(raw) > 0, raw

    def _process_line(self, raw: bytes) -> None:
        if self.type == httpParserTypes.REQUEST_PARSER:
            if self.protocol is not None and self.protocol.version is None:
                # We expect to receive entire proxy protocol v1 line
                # in one network read and don't expect partial packets
                self.protocol.parse(raw)
            else:
                # Ref: https://datatracker.ietf.org/doc/html/rfc2616#section-5.1
                line = raw.split(WHITESPACE, 2)
                if len(line) == 3:
                    self.method = line[0].upper()
                    self.set_url(line[1])
                    self.version = line[2]
                    self.state = httpParserStates.LINE_RCVD
                else:
                    # To avoid a possible attack vector, we raise exception
                    # if parser receives an invalid request line.
                    #
                    # TODO: Better to use raise HttpProtocolException,
                    # but we should solve circular import problem first.
                    raise ValueError('Invalid request line')
        else:
            line = raw.split(WHITESPACE, 2)
            self.version = line[0]
            self.code = line[1]
            self.reason = line[2]
            self.state = httpParserStates.LINE_RCVD

    def _process_header(self, raw: bytes) -> None:
        parts = raw.split(COLON, 1)
        self.add_header(
            parts[0].strip(),
            b'' if len(parts) == 1 else parts[1].strip(),
        )

    def _get_body_or_chunks(self) -> Optional[bytes]:
        return ChunkParser.to_chunks(self.body) \
            if self.body and self.is_chunked_encoded else \
            self.body

    def _set_line_attributes(self) -> None:
        if self.type == httpParserTypes.REQUEST_PARSER:
            if self.is_https_tunnel and self._url:
                self.host = self._url.hostname
                self.port = 443 if self._url.port is None else self._url.port
            elif self._url:
                self.host, self.port = self._url.hostname, self._url.port \
                    if self._url.port else DEFAULT_HTTP_PORT
            else:
                raise KeyError(
                    'Invalid request. Method: %r, Url: %r' %
                    (self.method, self._url),
                )
            self.path = self._url.remainder
