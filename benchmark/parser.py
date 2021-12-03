# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import httptools

from typing import Optional

from proxy.http.parser import HttpParser, httpParserTypes, httpParserStates


class HTTPToolsHandler:
    """A callback handler that works with the HTTPTools library."""

    def __init__(self):
        self.parser: Optional[HttpParser] = None

    def reset(self):
        """Resets the current request.

        Should be called after the message is complete.
        """
        self.parser = None

    def on_message_begin(self):
        """
        Called when a message has begun.
        """
        self.parser = HttpParser(httpParserTypes.REQUEST_PARSER)

    def on_header(self, name: bytes, value: bytes):
        """
        Called when a header is set.
        """
        # Decode the name and the values to get the header.
        assert self.parser
        self.parser.state = httpParserStates.RCVING_HEADERS
        self.parser.add_header(name, value)

    def on_body(self, body: bytes):
        """
        Called when the body is received.
        """
        assert self.parser
        self.parser.state = httpParserStates.RCVING_BODY
        if self.parser.body is None:
            self.parser.body = body
        else:
            self.parser.body += body

    def on_url(self, url: bytes):
        """
        Called when a URL is recieved.

        This is undocumented in the HTTPTools README.
        """
        assert self.parser
        self.parser.state = httpParserStates.LINE_RCVD
        self.parser.set_url(url)

    def on_message_complete(self):
        """
        Called when a message is complete.
        """
        self.parser.state = httpParserStates.COMPLETE


RAW_REQUEST = b'GET /http-route-example HTTP/1.1\r\nHost: localhost:8899\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n'


def parse_request_using_http_parser():
    r = HttpParser(httpParserTypes.REQUEST_PARSER)
    r.parse(RAW_REQUEST)
    # assert r.is_complete


def parse_request_using_http_tools():
    protocol = HTTPToolsHandler()
    r = httptools.HttpRequestParser(protocol)
    r.feed_data(RAW_REQUEST)
    # assert protocol.parser.is_complete
    # assert protocol.parser.host is None
    # assert protocol.parser.port == 80
    # assert protocol.parser.path == b'/http-route-example'
    # assert protocol.parser.code is None
    # assert protocol.parser.reason is None
    # assert protocol.parser.version is None
    # assert len(protocol.parser.headers) == 3
    # assert r.get_method() == b'GET'
    # assert r.get_http_version() == '1.1'
    # assert r.should_keep_alive() is True
    # assert r.should_upgrade() is False


# TL;DR - Node HTTP Parser is more than 30% faster compared to proxy.py HttpParser
# TODO: Benchmark with picco http parser
# TODO: Add option to use the fastest available parser if installed in the environment
if __name__ == '__main__':
    # for _ in range(100000):
    #     parse_request_using_http_parser()
    import timeit
    print(timeit.timeit(parse_request_using_http_parser, number=1000000))
    print(timeit.timeit(parse_request_using_http_tools, number=1000000))
