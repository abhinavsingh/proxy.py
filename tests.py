import unittest
from proxy import *
from proxy import bytes_, text_


class TestChunkParser(unittest.TestCase):

    def setUp(self):
        self.parser = ChunkParser()

    def test_chunk_parse(self):
        self.parser.parse(b''.join([
            b'4\r\n',
            b'Wiki\r\n',
            b'5\r\n',
            b'pedia\r\n',
            b'E\r\n',
            b' in\r\n\r\nchunks.\r\n',
            b'0\r\n',
            b'\r\n'
        ]))
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, CHUNK_PARSER_STATE_COMPLETE)


class TestHttpParser(unittest.TestCase):

    def setUp(self):
        self.parser = HttpParser()

    def test_get_full_parse(self):
        raw = text_(CRLF, encoding='utf-8').join([
            'GET %s HTTP/1.1',
            'Host: %s',
            text_(CRLF, encoding='utf-8')
        ])
        self.parser.parse(bytes_(raw % ('https://example.com/path/dir/?a=b&c=d#p=q', 'example.com')))
        self.assertEqual(self.parser.build_url(), b'/path/dir/?a=b&c=d#p=q')
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'example.com')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertDictContainsSubset({b'host': (b'Host', b'example.com')}, self.parser.headers)
        self.assertEqual(bytes_(raw % ('/path/dir/?a=b&c=d#p=q', 'example.com')),
                         self.parser.build(del_headers=[b'host'], add_headers=[(b'Host', b'example.com')]))

    def test_build_url_none(self):
        self.assertEqual(self.parser.build_url(), b'/None')

    def test_line_rcvd_to_rcving_headers_state_change(self):
        self.parser.parse(b'GET http://localhost HTTP/1.1')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_INITIALIZED)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

    def test_get_partial_parse1(self):
        self.parser.parse(CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1'
        ]))
        self.assertEqual(self.parser.method, None)
        self.assertEqual(self.parser.url, None)
        self.assertEqual(self.parser.version, None)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_INITIALIZED)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)

        self.parser.parse(b'Host: localhost:8080')
        self.assertDictEqual(self.parser.headers, dict())
        self.assertEqual(self.parser.buffer, b'Host: localhost:8080')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)

        self.parser.parse(CRLF * 2)
        self.assertDictContainsSubset({b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_get_partial_parse2(self):
        self.parser.parse(CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1',
            b'Host: '
        ]))
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.buffer, b'Host: ')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)

        self.parser.parse(b'localhost:8080' + CRLF)
        self.assertDictContainsSubset({b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse(b'Content-Type: text/plain' + CRLF)
        self.assertEqual(self.parser.buffer, b'')
        self.assertDictContainsSubset({b'content-type': (b'Content-Type', b'text/plain')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_post_full_parse(self):
        raw = text_(CRLF).join([
            'POST %s HTTP/1.1',
            'Host: localhost',
            'Content-Length: 7',
            'Content-Type: application/x-www-form-urlencoded' + text_(CRLF, encoding='utf-8'),
            'a=b&c=d'
        ])
        self.parser.parse(bytes_(raw % 'http://localhost'))
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertDictContainsSubset({b'content-type': (b'Content-Type', b'application/x-www-form-urlencoded')},
                                      self.parser.headers)
        self.assertDictContainsSubset({b'content-length': (b'Content-Length', b'7')}, self.parser.headers)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % '/'))

    def test_post_partial_parse(self):
        self.parser.parse(CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded'
        ]))
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_HEADERS_COMPLETE)

        self.parser.parse(b'a=b')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_BODY)
        self.assertEqual(self.parser.body, b'a=b')
        self.assertEqual(self.parser.buffer, b'')

        self.parser.parse(b'&c=d')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')

    def test_response_parse(self):
        self.parser.type = HTTP_RESPONSE_PARSER
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
            '<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n'
        ]))
        self.assertEqual(self.parser.code, b'301')
        self.assertEqual(self.parser.reason, b'Moved Permanently')
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.body,
                         b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
                         '<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
                         '<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertDictContainsSubset({b'content-length': (b'Content-Length', b'219')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_response_partial_parse(self):
        self.parser.type = HTTP_RESPONSE_PARSER
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
        self.assertDictContainsSubset({b'x-frame-options': (b'X-Frame-Options', b'SAMEORIGIN')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_HEADERS_COMPLETE)
        self.parser.parse(
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            '<TITLE>301 Moved</TITLE></HEAD>')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_BODY)
        self.parser.parse(
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            '<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_chunked_response_parse(self):
        self.parser.type = HTTP_RESPONSE_PARSER
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
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)


class MockConnection(object):

    def __init__(self, b=b''):
        self.buffer = b

    def recv(self, b=8192):
        data = self.buffer[:b]
        self.buffer = self.buffer[b:]
        return data

    def send(self, data):
        return len(data)

    def queue(self, data):
        self.buffer += data


class TestProxy(unittest.TestCase):

    def setUp(self):
        self._conn = MockConnection()
        self._addr = ('127.0.0.1', 54382)
        self.proxy = Proxy(Client(self._conn, self._addr))

    def test_http_get(self):
        self.proxy.client.conn.queue(b'GET http://httpbin.org/get HTTP/1.1' + CRLF)
        self.proxy._process_request(self.proxy.client.recv())
        self.assertNotEqual(self.proxy.request.state, HTTP_PARSER_STATE_COMPLETE)

        self.proxy.client.conn.queue(CRLF.join([
            b'User-Agent: curl/7.27.0',
            b'Host: httpbin.org',
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            CRLF
        ]))

        self.proxy._process_request(self.proxy.client.recv())
        self.assertEqual(self.proxy.request.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(self.proxy.server.addr, (b'httpbin.org', 80))

        self.proxy.server.flush()
        self.assertEqual(self.proxy.server.buffer_size(), 0)

        data = self.proxy.server.recv()
        while data:
            self.proxy._process_response(data)
            if self.proxy.response.state == HTTP_PARSER_STATE_COMPLETE:
                break
            data = self.proxy.server.recv()

        self.assertEqual(self.proxy.response.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(int(self.proxy.response.code), 200)

    def test_https_get(self):
        self.proxy.client.conn.queue(CRLF.join([
            b'CONNECT httpbin.org:80 HTTP/1.1',
            b'Host: httpbin.org:80',
            b'User-Agent: curl/7.27.0',
            b'Proxy-Connection: Keep-Alive',
            CRLF
        ]))
        self.proxy._process_request(self.proxy.client.recv())
        self.assertFalse(self.proxy.server is None)
        self.assertEqual(self.proxy.client.buffer, self.proxy.connection_established_pkt)

        parser = HttpParser(HTTP_RESPONSE_PARSER)
        parser.parse(self.proxy.client.buffer)
        self.assertEqual(parser.state, HTTP_PARSER_STATE_HEADERS_COMPLETE)
        self.assertEqual(int(parser.code), 200)

        self.proxy.client.flush()
        self.assertEqual(self.proxy.client.buffer_size(), 0)

        self.proxy.client.conn.queue(CRLF.join([
            b'GET /user-agent HTTP/1.1',
            b'Host: httpbin.org',
            b'User-Agent: curl/7.27.0',
            CRLF
        ]))
        self.proxy._process_request(self.proxy.client.recv())
        self.proxy.server.flush()
        self.assertEqual(self.proxy.server.buffer_size(), 0)

        parser = HttpParser(HTTP_RESPONSE_PARSER)
        data = self.proxy.server.recv()
        while data:
            parser.parse(data)
            if parser.state == HTTP_PARSER_STATE_COMPLETE:
                break
            data = self.proxy.server.recv()

        self.assertEqual(parser.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(int(parser.code), 200)

    def test_proxy_connection_failed(self):
        with self.assertRaises(ProxyConnectionFailed):
            self.proxy._process_request(CRLF.join([
                b'GET http://unknown.domain HTTP/1.1',
                b'Host: unknown.domain',
                CRLF
            ]))


if __name__ == '__main__':
    unittest.main()
