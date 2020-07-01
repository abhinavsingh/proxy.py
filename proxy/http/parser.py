# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from urllib import parse as urlparse
from typing import TypeVar, NamedTuple, Optional, Dict, Type, Tuple, List

from .methods import httpMethods
from .chunk_parser import ChunkParser, chunkParserStates

from ..common.constants import DEFAULT_DISABLE_HEADERS, COLON, CRLF, WHITESPACE, HTTP_1_1, DEFAULT_HTTP_PORT
from ..common.utils import build_http_request, build_http_response, find_http_line, text_


HttpParserStates = NamedTuple('HttpParserStates', [
    ('INITIALIZED', int),
    ('LINE_RCVD', int),
    ('RCVING_HEADERS', int),
    ('HEADERS_COMPLETE', int),
    ('RCVING_BODY', int),
    ('COMPLETE', int),
])
httpParserStates = HttpParserStates(1, 2, 3, 4, 5, 6)

HttpParserTypes = NamedTuple('HttpParserTypes', [
    ('REQUEST_PARSER', int),
    ('RESPONSE_PARSER', int),
])
httpParserTypes = HttpParserTypes(1, 2)


T = TypeVar('T', bound='HttpParser')


class HttpParser:
    """HTTP request/response parser."""

    def __init__(self, parser_type: int) -> None:
        self.type: int = parser_type
        self.state: int = httpParserStates.INITIALIZED

        # Total size of raw bytes passed for parsing
        self.total_size: int = 0

        # Buffer to hold unprocessed bytes
        self.buffer: bytes = b''

        self.headers: Dict[bytes, Tuple[bytes, bytes]] = dict()
        self.body: Optional[bytes] = None

        self.method: Optional[bytes] = None
        self.url: Optional[urlparse.SplitResultBytes] = None
        self.code: Optional[bytes] = None
        self.reason: Optional[bytes] = None
        self.version: Optional[bytes] = None

        self.chunk_parser: Optional[ChunkParser] = None

        # This cleans up developer APIs as Python urlparse.urlsplit behaves differently
        # for incoming proxy request and incoming web request.  Web request is the one
        # which is broken.
        self.host: Optional[bytes] = None
        self.port: Optional[int] = None
        self.path: Optional[bytes] = None

    @classmethod
    def request(cls: Type[T], raw: bytes) -> T:
        parser = cls(httpParserTypes.REQUEST_PARSER)
        parser.parse(raw)
        return parser

    @classmethod
    def response(cls: Type[T], raw: bytes) -> T:
        parser = cls(httpParserTypes.RESPONSE_PARSER)
        parser.parse(raw)
        return parser

    def header(self, key: bytes) -> bytes:
        if key.lower() not in self.headers:
            raise KeyError('%s not found in headers', text_(key))
        return self.headers[key.lower()][1]

    def has_header(self, key: bytes) -> bool:
        return key.lower() in self.headers

    def add_header(self, key: bytes, value: bytes) -> None:
        self.headers[key.lower()] = (key, value)

    def add_headers(self, headers: List[Tuple[bytes, bytes]]) -> None:
        for (key, value) in headers:
            self.add_header(key, value)

    def del_header(self, header: bytes) -> None:
        if header.lower() in self.headers:
            del self.headers[header.lower()]

    def del_headers(self, headers: List[bytes]) -> None:
        for key in headers:
            self.del_header(key.lower())

    def set_url(self, url: bytes) -> None:
        # Work around with urlsplit semantics.
        #
        # For CONNECT requests, request line contains
        # upstream_host:upstream_port which is not complaint
        # with urlsplit, which expects a fully qualified url.
        if self.method == b'CONNECT':
            url = b'https://' + url
        self.url = urlparse.urlsplit(url)
        self.set_line_attributes()

    def set_line_attributes(self) -> None:
        if self.type == httpParserTypes.REQUEST_PARSER:
            if self.method == httpMethods.CONNECT and self.url:
                self.host = self.url.hostname
                self.port = 443 if self.url.port is None else self.url.port
            elif self.url:
                self.host, self.port = self.url.hostname, self.url.port \
                    if self.url.port else DEFAULT_HTTP_PORT
            else:
                raise KeyError(
                    'Invalid request. Method: %r, Url: %r' %
                    (self.method, self.url))
            self.path = self.build_path()

    def is_chunked_encoded(self) -> bool:
        return b'transfer-encoding' in self.headers and \
               self.headers[b'transfer-encoding'][1].lower() == b'chunked'

    def body_expected(self) -> bool:
        return (b'content-length' in self.headers and
                int(self.header(b'content-length')) > 0) or \
            self.is_chunked_encoded()

    def parse(self, raw: bytes) -> None:
        """Parses Http request out of raw bytes.

        Check HttpParser state after parse has successfully returned."""
        self.total_size += len(raw)
        raw = self.buffer + raw
        self.buffer = b''

        more = True if len(raw) > 0 else False
        while more and self.state != httpParserStates.COMPLETE:
            if self.state in (
                    httpParserStates.HEADERS_COMPLETE,
                    httpParserStates.RCVING_BODY):
                if b'content-length' in self.headers:
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
                elif self.is_chunked_encoded():
                    if not self.chunk_parser:
                        self.chunk_parser = ChunkParser()
                    raw = self.chunk_parser.parse(raw)
                    if self.chunk_parser.state == chunkParserStates.COMPLETE:
                        self.body = self.chunk_parser.body
                        self.state = httpParserStates.COMPLETE
                    more = False
                else:
                    raise NotImplementedError('Parser shouldn\'t have reached here')
            else:
                more, raw = self.process(raw)
        self.buffer = raw

    def process(self, raw: bytes) -> Tuple[bool, bytes]:
        """Returns False when no CRLF could be found in received bytes."""
        line, raw = find_http_line(raw)
        if line is None:
            return False, raw

        if self.state == httpParserStates.INITIALIZED:
            self.process_line(line)
            self.state = httpParserStates.LINE_RCVD
        elif self.state in (httpParserStates.LINE_RCVD, httpParserStates.RCVING_HEADERS):
            if self.state == httpParserStates.LINE_RCVD:
                # LINE_RCVD state is equivalent to RCVING_HEADERS
                self.state = httpParserStates.RCVING_HEADERS
            if line.strip() == b'':  # Blank line received.
                self.state = httpParserStates.HEADERS_COMPLETE
            else:
                self.process_header(line)

        # When server sends a response line without any header or body e.g.
        # HTTP/1.1 200 Connection established\r\n\r\n
        if self.state == httpParserStates.LINE_RCVD and \
                self.type == httpParserTypes.RESPONSE_PARSER and \
                raw == CRLF:
            self.state = httpParserStates.COMPLETE
        elif self.state == httpParserStates.HEADERS_COMPLETE and \
                not self.body_expected() and \
                raw == b'':
            self.state = httpParserStates.COMPLETE

        return len(raw) > 0, raw

    def process_line(self, raw: bytes) -> None:
        line = raw.split(WHITESPACE)
        if self.type == httpParserTypes.REQUEST_PARSER:
            self.method = line[0].upper()
            self.set_url(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = WHITESPACE.join(line[2:])

    def process_header(self, raw: bytes) -> None:
        parts = raw.split(COLON)
        key = parts[0].strip()
        value = COLON.join(parts[1:]).strip()
        self.add_headers([(key, value)])

    def build_path(self) -> bytes:
        if not self.url:
            return b'/None'
        url = self.url.path
        if url == b'':
            url = b'/'
        if not self.url.query == b'':
            url += b'?' + self.url.query
        if not self.url.fragment == b'':
            url += b'#' + self.url.fragment
        return url

    def build(self, disable_headers: Optional[List[bytes]] = None) -> bytes:
        """Rebuild the request object."""
        assert self.method and self.version and self.path and self.type == httpParserTypes.REQUEST_PARSER
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS
        body: Optional[bytes] = ChunkParser.to_chunks(self.body) \
            if self.is_chunked_encoded() and self.body else \
            self.body
        return build_http_request(
            self.method, self.path, self.version,
            headers={} if not self.headers else {self.headers[k][0]: self.headers[k][1] for k in self.headers if
                                                 k.lower() not in disable_headers},
            body=body
        )

    def build_response(self) -> bytes:
        """Rebuild the response object."""
        assert self.code and self.version and self.body and self.type == httpParserTypes.RESPONSE_PARSER
        return build_http_response(
            status_code=int(self.code),
            protocol_version=self.version,
            reason=self.reason,
            headers={} if not self.headers else {self.headers[k][0]: self.headers[k][1] for k in self.headers},
            body=self.body if not self.is_chunked_encoded() else ChunkParser.to_chunks(self.body))

    def has_upstream_server(self) -> bool:
        """Host field SHOULD be None for incoming local WebServer requests."""
        return True if self.host is not None else False

    def is_http_1_1_keep_alive(self) -> bool:
        return self.version == HTTP_1_1 and \
            (not self.has_header(b'Connection') or
             self.header(b'Connection').lower() == b'keep-alive')

    def is_connection_upgrade(self) -> bool:
        return self.version == HTTP_1_1 and \
            self.has_header(b'Connection') and \
            self.has_header(b'Upgrade')
