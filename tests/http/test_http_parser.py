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

from proxy.common.constants import CRLF
from proxy.common.utils import build_http_request, find_http_line, build_http_response, build_http_header, bytes_
from proxy.http.methods import httpMethods
from proxy.http.codes import httpStatusCodes
from proxy.http.parser import HttpParser, httpParserTypes, httpParserStates


class TestHttpParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = HttpParser(httpParserTypes.REQUEST_PARSER)

    def test_build_request(self) -> None:
        self.assertEqual(
            build_http_request(
                b'GET', b'http://localhost:12345', b'HTTP/1.1'),
            CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                CRLF
            ]))
        self.assertEqual(
            build_http_request(b'GET', b'http://localhost:12345', b'HTTP/1.1',
                               headers={b'key': b'value'}),
            CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                CRLF
            ]))
        self.assertEqual(
            build_http_request(b'GET', b'http://localhost:12345', b'HTTP/1.1',
                               headers={b'key': b'value'},
                               body=b'Hello from py'),
            CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                CRLF
            ]) + b'Hello from py')

    def test_build_response(self) -> None:
        self.assertEqual(
            build_http_response(
                200, reason=b'OK', protocol_version=b'HTTP/1.1'),
            CRLF.join([
                b'HTTP/1.1 200 OK',
                CRLF
            ]))
        self.assertEqual(
            build_http_response(200, reason=b'OK', protocol_version=b'HTTP/1.1',
                                headers={b'key': b'value'}),
            CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                CRLF
            ]))

    def test_build_response_adds_content_length_header(self) -> None:
        body = b'Hello world!!!'
        self.assertEqual(
            build_http_response(200, reason=b'OK', protocol_version=b'HTTP/1.1',
                                headers={b'key': b'value'},
                                body=body),
            CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                b'Content-Length: ' + bytes_(len(body)),
                CRLF
            ]) + body)

    def test_build_header(self) -> None:
        self.assertEqual(
            build_http_header(
                b'key', b'value'), b'key: value')

    def test_header_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.parser.header(b'not-found')

    def test_has_header(self) -> None:
        self.parser.add_header(b'key', b'value')
        self.assertFalse(self.parser.has_header(b'not-found'))
        self.assertTrue(self.parser.has_header(b'key'))

    def test_set_host_port_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.parser.set_line_attributes()

    def test_find_line(self) -> None:
        self.assertEqual(
            find_http_line(
                b'CONNECT python.org:443 HTTP/1.0\r\n\r\n'),
            (b'CONNECT python.org:443 HTTP/1.0',
             CRLF))

    def test_find_line_returns_None(self) -> None:
        self.assertEqual(
            find_http_line(b'CONNECT python.org:443 HTTP/1.0'),
            (None,
             b'CONNECT python.org:443 HTTP/1.0'))

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
            CRLF
        ])
        pkt = raw % (b'https://example.com/path/dir/?a=b&c=d#p=q',
                     b'example.com')
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assertEqual(self.parser.build_url(), b'/path/dir/?a=b&c=d#p=q')
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'example.com')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'example.com')}, self.parser.headers)
        self.parser.del_headers([b'host'])
        self.parser.add_headers([(b'Host', b'example.com')])
        self.assertEqual(
            raw %
            (b'/path/dir/?a=b&c=d#p=q',
             b'example.com'),
            self.parser.build())

    def test_build_url_none(self) -> None:
        self.assertEqual(self.parser.build_url(), b'/None')

    def test_line_rcvd_to_rcving_headers_state_change(self) -> None:
        pkt = b'GET http://localhost HTTP/1.1'
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assert_state_change_with_crlf(
            httpParserStates.INITIALIZED,
            httpParserStates.LINE_RCVD,
            httpParserStates.COMPLETE)

    def test_get_partial_parse1(self) -> None:
        pkt = CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1'
        ])
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assertEqual(self.parser.method, None)
        self.assertEqual(self.parser.url, None)
        self.assertEqual(self.parser.version, None)
        self.assertEqual(
            self.parser.state,
            httpParserStates.INITIALIZED)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.total_size, len(pkt) + len(CRLF))
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)

        host_hdr = b'Host: localhost:8080'
        self.parser.parse(host_hdr)
        self.assertEqual(self.parser.total_size,
                         len(pkt) + len(CRLF) + len(host_hdr))
        self.assertDictEqual(self.parser.headers, dict())
        self.assertEqual(self.parser.buffer, b'Host: localhost:8080')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)

        self.parser.parse(CRLF * 2)
        self.assertEqual(self.parser.total_size, len(pkt) +
                         (3 * len(CRLF)) + len(host_hdr))
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_get_partial_parse2(self) -> None:
        self.parser.parse(CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1',
            b'Host: '
        ]))
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.buffer, b'Host: ')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)

        self.parser.parse(b'localhost:8080' + CRLF)
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_HEADERS)

        self.parser.parse(b'Content-Type: text/plain' + CRLF)
        self.assertEqual(self.parser.buffer, b'')
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'text/plain')}, self.parser.headers)
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_HEADERS)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_post_full_parse(self) -> None:
        raw = CRLF.join([
            b'POST %s HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded' + CRLF,
            b'a=b&c=d'
        ])
        self.parser.parse(raw % b'http://localhost')
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'application/x-www-form-urlencoded')}, self.parser.headers)
        self.assertDictContainsSubset(
            {b'content-length': (b'Content-Length', b'7')}, self.parser.headers)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % b'/'))

    def assert_state_change_with_crlf(self,
                                      initial_state: int,
                                      next_state: int,
                                      final_state: int) -> None:
        self.assertEqual(self.parser.state, initial_state)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, next_state)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, final_state)

    def test_post_partial_parse(self) -> None:
        self.parser.parse(CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded'
        ]))
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assert_state_change_with_crlf(
            httpParserStates.RCVING_HEADERS,
            httpParserStates.RCVING_HEADERS,
            httpParserStates.HEADERS_COMPLETE)

        self.parser.parse(b'a=b')
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_BODY)
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
        self.assertEqual(self.parser.method, b'CONNECT')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_request_parse_without_content_length(self) -> None:
        """Case when incoming request doesn't contain a content-length header.

        From http://w3-org.9356.n7.nabble.com/POST-with-empty-body-td103965.html
        'A POST with no content-length and no body is equivalent to a POST with Content-Length: 0
        and nothing following, as could perfectly happen when you upload an empty file for instance.'

        See https://github.com/abhinavsingh/py/issues/20 for details.
        """
        self.parser.parse(CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Type: application/x-www-form-urlencoded',
            CRLF
        ]))
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_response_parse_without_content_length(self) -> None:
        """Case when server response doesn't contain a content-length header for non-chunk response types.

        HttpParser by itself has no way to know if more data should be expected.
        In example below, parser reaches state httpParserStates.HEADERS_COMPLETE
        and it is responsibility of callee to change state to httpParserStates.COMPLETE
        when server stream closes.

        See https://github.com/abhinavsingh/py/issues/20 for details.
        """
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b'HTTP/1.0 200 OK' + CRLF)
        self.assertEqual(self.parser.code, b'200')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, httpParserStates.LINE_RCVD)
        self.parser.parse(CRLF.join([
            b'Server: BaseHTTP/0.3 Python/2.7.10',
            b'Date: Thu, 13 Dec 2018 16:24:09 GMT',
            CRLF
        ]))
        self.assertEqual(
            self.parser.state,
            httpParserStates.HEADERS_COMPLETE)

    def test_response_parse(self) -> None:
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b''.join([
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
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n'
        ]))
        self.assertEqual(self.parser.code, b'301')
        self.assertEqual(self.parser.reason, b'Moved Permanently')
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(
            self.parser.body,
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertDictContainsSubset(
            {b'content-length': (b'Content-Length', b'219')}, self.parser.headers)
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_response_partial_parse(self) -> None:
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b''.join([
            b'HTTP/1.1 301 Moved Permanently\r\n',
            b'Location: http://www.google.com/\r\n',
            b'Content-Type: text/html; charset=UTF-8\r\n',
            b'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
            b'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
            b'Cache-Control: public, max-age=2592000\r\n',
            b'Server: gws\r\n',
            b'Content-Length: 219\r\n',
            b'X-XSS-Protection: 1; mode=block\r\n',
            b'X-Frame-Options: SAMEORIGIN\r\n'
        ]))
        self.assertDictContainsSubset(
            {b'x-frame-options': (b'X-Frame-Options', b'SAMEORIGIN')}, self.parser.headers)
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_HEADERS)
        self.parser.parse(b'\r\n')
        self.assertEqual(
            self.parser.state,
            httpParserStates.HEADERS_COMPLETE)
        self.parser.parse(
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>')
        self.assertEqual(
            self.parser.state,
            httpParserStates.RCVING_BODY)
        self.parser.parse(
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_chunked_response_parse(self) -> None:
        self.parser.type = httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b''.join([
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
            b'\r\n'
        ]))
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)

    def test_pipelined_response_parse(self) -> None:
        response = build_http_response(
            httpStatusCodes.OK, reason=b'OK',
            headers={
                b'Content-Length': b'15'
            },
            body=b'{"key":"value"}',
        )
        self.assert_pipeline_response(response)

    def test_pipelined_chunked_response_parse(self) -> None:
        response = build_http_response(
            httpStatusCodes.OK, reason=b'OK',
            headers={
                b'Transfer-Encoding': b'chunked',
                b'Content-Type': b'application/json',
            },
            body=b'f\r\n{"key":"value"}\r\n0\r\n\r\n'
        )
        self.assert_pipeline_response(response)

    def assert_pipeline_response(self, response: bytes) -> None:
        self.parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.parser.parse(response + response)
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
        self.parser.parse(build_http_request(
            httpMethods.POST, b'http://example.org/',
            headers={
                b'Transfer-Encoding': b'chunked',
                b'Content-Type': b'application/json',
            },
            body=b'f\r\n{"key":"value"}\r\n0\r\n\r\n'))
        self.assertEqual(self.parser.body, b'{"key":"value"}')
        self.assertEqual(self.parser.state, httpParserStates.COMPLETE)
        self.assertEqual(self.parser.build(), build_http_request(
            httpMethods.POST, b'/',
            headers={
                b'Transfer-Encoding': b'chunked',
                b'Content-Type': b'application/json',
            },
            body=b'f\r\n{"key":"value"}\r\n0\r\n\r\n'))

    def test_is_http_1_1_keep_alive(self) -> None:
        self.parser.parse(build_http_request(
            httpMethods.GET, b'/'
        ))
        self.assertTrue(self.parser.is_http_1_1_keep_alive())

    def test_is_http_1_1_keep_alive_with_non_close_connection_header(
            self) -> None:
        self.parser.parse(build_http_request(
            httpMethods.GET, b'/',
            headers={
                b'Connection': b'keep-alive',
            }
        ))
        self.assertTrue(self.parser.is_http_1_1_keep_alive())

    def test_is_not_http_1_1_keep_alive_with_close_header(self) -> None:
        self.parser.parse(build_http_request(
            httpMethods.GET, b'/',
            headers={
                b'Connection': b'close',
            }
        ))
        self.assertFalse(self.parser.is_http_1_1_keep_alive())

    def test_is_not_http_1_1_keep_alive_for_http_1_0(self) -> None:
        self.parser.parse(build_http_request(
            httpMethods.GET, b'/', protocol_version=b'HTTP/1.0',
        ))
        self.assertFalse(self.parser.is_http_1_1_keep_alive())
