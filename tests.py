import unittest
import proxy
from proxy import *

class TestChunkParser(unittest.TestCase):

    def setUp(self):
        self.parser = ChunkParser()

    def test_chunk_parse(self):
        self.parser.parse(''.join([
            '4\r\n',
            'Wiki\r\n',
            '5\r\n',
            'pedia\r\n',
            'E\r\n',
            ' in\r\n\r\nchunks.\r\n',
            '0\r\n',
            '\r\n'
        ]))
        self.assertEqual(self.parser.chunk, '')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, 'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, CHUNK_PARSER_STATE_COMPLETE)

class TestHttpParser(unittest.TestCase):

    def setUp(self):
        self.parser = HttpParser()

    def test_get_full_parse(self):
        raw = CRLF.join([
            "GET %s HTTP/1.1",
            "Host: %s",
            CRLF
        ])
        self.parser.parse(raw % ('https://example.com/path/dir/?a=b&c=d#p=q', 'example.com'))
        self.assertEqual(self.parser.build_url(), '/path/dir/?a=b&c=d#p=q')
        self.assertEqual(self.parser.method, "GET")
        self.assertEqual(self.parser.url.hostname, "example.com")
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, "HTTP/1.1")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertDictContainsSubset({'host':('Host', 'example.com')}, self.parser.headers)
        self.assertEqual(raw % ('/path/dir/?a=b&c=d#p=q', 'example.com'), self.parser.build(del_headers=['host'], add_headers=[('Host', 'example.com')]))

    def test_build_url_none(self):
        self.assertEqual(self.parser.build_url(), '/None')

    def test_line_rcvd_to_rcving_headers_state_change(self):
        self.parser.parse("GET http://localhost HTTP/1.1")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_INITIALIZED)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)
        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

    def test_get_partial_parse1(self):
        self.parser.parse(CRLF.join([
            "GET http://localhost:8080 HTTP/1.1"
        ]))
        self.assertEqual(self.parser.method, None)
        self.assertEqual(self.parser.url, None)
        self.assertEqual(self.parser.version, None)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_INITIALIZED)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.method, "GET")
        self.assertEqual(self.parser.url.hostname, "localhost")
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, "HTTP/1.1")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)

        self.parser.parse("Host: localhost:8080")
        self.assertDictEqual(self.parser.headers, dict())
        self.assertEqual(self.parser.buffer, "Host: localhost:8080")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)

        self.parser.parse(CRLF*2)
        self.assertDictContainsSubset({'host':('Host', 'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_get_partial_parse2(self):
        self.parser.parse(CRLF.join([
            "GET http://localhost:8080 HTTP/1.1",
            "Host: "
        ]))
        self.assertEqual(self.parser.method, "GET")
        self.assertEqual(self.parser.url.hostname, "localhost")
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, "HTTP/1.1")
        self.assertEqual(self.parser.buffer, "Host: ")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_LINE_RCVD)

        self.parser.parse("localhost:8080%s" % CRLF)
        self.assertDictContainsSubset({'host': ('Host', 'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.buffer, "")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse("Content-Type: text/plain%s" % CRLF)
        self.assertEqual(self.parser.buffer, "")
        self.assertDictContainsSubset({'content-type': ('Content-Type', 'text/plain')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_post_full_parse(self):
        raw = CRLF.join([
            "POST %s HTTP/1.1",
            "Host: localhost",
            "Content-Length: 7",
            "Content-Type: application/x-www-form-urlencoded%s" % CRLF,
            "a=b&c=d"
        ])
        self.parser.parse(raw % 'http://localhost')
        self.assertEqual(self.parser.method, "POST")
        self.assertEqual(self.parser.url.hostname, "localhost")
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, "HTTP/1.1")
        self.assertDictContainsSubset({'content-type': ('Content-Type', 'application/x-www-form-urlencoded')}, self.parser.headers)
        self.assertDictContainsSubset({'content-length': ('Content-Length', '7')}, self.parser.headers)
        self.assertEqual(self.parser.body, "a=b&c=d")
        self.assertEqual(self.parser.buffer, "")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % '/'))

    def test_post_partial_parse(self):
        self.parser.parse(CRLF.join([
            "POST http://localhost HTTP/1.1",
            "Host: localhost",
            "Content-Length: 7",
            "Content-Type: application/x-www-form-urlencoded"
        ]))
        self.assertEqual(self.parser.method, "POST")
        self.assertEqual(self.parser.url.hostname, "localhost")
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, "HTTP/1.1")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)

        self.parser.parse(CRLF)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_HEADERS_COMPLETE)

        self.parser.parse("a=b")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_BODY)
        self.assertEqual(self.parser.body, "a=b")
        self.assertEqual(self.parser.buffer, "")

        self.parser.parse("&c=d")
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(self.parser.body, "a=b&c=d")
        self.assertEqual(self.parser.buffer, "")

    def test_response_parse(self):
        self.parser.type = HTTP_RESPONSE_PARSER
        self.parser.parse(''.join([
            'HTTP/1.1 301 Moved Permanently\r\n',
            'Location: http://www.google.com/\r\n',
            'Content-Type: text/html; charset=UTF-8\r\n',
            'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
            'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
            'Cache-Control: public, max-age=2592000\r\n',
            'Server: gws\r\n',
            'Content-Length: 219\r\n',
            'X-XSS-Protection: 1; mode=block\r\n',
            'X-Frame-Options: SAMEORIGIN\r\n\r\n',
            '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD>',
            '<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n'
        ]))
        self.assertEqual(self.parser.code, '301')
        self.assertEqual(self.parser.reason, 'Moved Permanently')
        self.assertEqual(self.parser.version, 'HTTP/1.1')
        self.assertEqual(self.parser.body, '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertDictContainsSubset({'content-length': ('Content-Length', '219')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_response_partial_parse(self):
        self.parser.type = HTTP_RESPONSE_PARSER
        self.parser.parse(''.join([
            'HTTP/1.1 301 Moved Permanently\r\n',
            'Location: http://www.google.com/\r\n',
            'Content-Type: text/html; charset=UTF-8\r\n',
            'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
            'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
            'Cache-Control: public, max-age=2592000\r\n',
            'Server: gws\r\n',
            'Content-Length: 219\r\n',
            'X-XSS-Protection: 1; mode=block\r\n',
            'X-Frame-Options: SAMEORIGIN\r\n'
        ]))
        self.assertDictContainsSubset({'x-frame-options': ('X-Frame-Options', 'SAMEORIGIN')}, self.parser.headers)
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_HEADERS)
        self.parser.parse('\r\n')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_HEADERS_COMPLETE)
        self.parser.parse('<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD>')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_RCVING_BODY)
        self.parser.parse('<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

    def test_chunked_response_parse(self):
        self.parser.type = HTTP_RESPONSE_PARSER
        self.parser.parse(''.join([
            'HTTP/1.1 200 OK\r\n',
            'Content-Type: application/json\r\n',
            'Date: Wed, 22 May 2013 15:08:15 GMT\r\n',
            'Server: gunicorn/0.16.1\r\n',
            'transfer-encoding: chunked\r\n',
            'Connection: keep-alive\r\n\r\n',
            '4\r\n',
            'Wiki\r\n',
            '5\r\n',
            'pedia\r\n',
            'E\r\n',
            ' in\r\n\r\nchunks.\r\n',
            '0\r\n',
            '\r\n'
        ]))
        self.assertEqual(self.parser.body, 'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, HTTP_PARSER_STATE_COMPLETE)

class MockConnection(object):
    
    def __init__(self, buffer=''):
        self.buffer = buffer
    
    def recv(self, bytes=8192):
        data = self.buffer[:bytes]
        self.buffer = self.buffer[bytes:]
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
        self.proxy.client.conn.queue("GET http://httpbin.org/get HTTP/1.1%s" % CRLF)
        self.proxy._process_request(self.proxy.client.recv())
        self.assertNotEqual(self.proxy.request.state, HTTP_PARSER_STATE_COMPLETE)

        self.proxy.client.conn.queue(CRLF.join([
            "User-Agent: curl/7.27.0",
            "Host: httpbin.org",
            "Accept: */*",
            "Proxy-Connection: Keep-Alive",
            CRLF
        ]))
        
        self.proxy._process_request(self.proxy.client.recv())
        self.assertEqual(self.proxy.request.state, HTTP_PARSER_STATE_COMPLETE)
        self.assertEqual(self.proxy.server.addr, ("httpbin.org", 80))
        
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
            "CONNECT httpbin.org:80 HTTP/1.1",
            "Host: httpbin.org:80",
            "User-Agent: curl/7.27.0",
            "Proxy-Connection: Keep-Alive",
            CRLF
        ]))
        self.proxy._process_request(self.proxy.client.recv())
        self.assertFalse(self.proxy.server == None)
        self.assertEqual(self.proxy.client.buffer, self.proxy.connection_established_pkt)
        
        parser = HttpParser(HTTP_RESPONSE_PARSER)
        parser.parse(self.proxy.client.buffer)
        self.assertEqual(parser.state, HTTP_PARSER_STATE_HEADERS_COMPLETE)
        self.assertEqual(int(parser.code), 200)
        
        self.proxy.client.flush()
        self.assertEqual(self.proxy.client.buffer_size(), 0)
        
        self.proxy.client.conn.queue(CRLF.join([
            "GET /user-agent HTTP/1.1",
            "Host: httpbin.org",
            "User-Agent: curl/7.27.0",
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
                "GET http://unknown.domain HTTP/1.1",
                "Host: unknown.domain",
                CRLF
            ]))

if __name__ == '__main__':
    unittest.main()
