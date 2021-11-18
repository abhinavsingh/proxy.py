# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
import unittest
import selectors
import base64

from typing import cast
from unittest import mock

from proxy.common.plugins import Plugins
from proxy.common.flag import FlagParser
from proxy.common.version import __version__
from proxy.common.utils import bytes_
from proxy.common.constants import CRLF, PLUGIN_HTTP_PROXY, PLUGIN_PROXY_AUTH, PLUGIN_WEB_SERVER
from proxy.core.connection import TcpClientConnection
from proxy.http.parser import HttpParser
from proxy.http.proxy import HttpProxyPlugin
from proxy.http.parser import httpParserStates, httpParserTypes
from proxy.http.exception import ProxyAuthenticationFailed, ProxyConnectionFailed
from proxy.http import HttpProtocolHandler


class TestHttpProtocolHandler(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(
        self,
        mock_fromfd: mock.Mock,
        mock_selector: mock.Mock,
    ) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = mock_fromfd.return_value

        self.http_server_port = 65535
        self.flags = FlagParser.initialize(threaded=True)
        self.flags.plugins = Plugins.load([
            bytes_(PLUGIN_HTTP_PROXY),
            bytes_(PLUGIN_WEB_SERVER),
        ])

        self.mock_selector = mock_selector
        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr), flags=self.flags,
        )
        self.protocol_handler.initialize()

    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_http_get(self, mock_server_connection: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0
        self.mock_selector_for_client_read_read_server_write(
            self.mock_selector, server,
        )

        # Send request line
        assert self.http_server_port is not None
        self._conn.recv.return_value = (
            b'GET http://localhost:%d HTTP/1.1' %
            self.http_server_port
        ) + CRLF
        self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.LINE_RCVD,
        )
        self.assertNotEqual(
            self.protocol_handler.request.state,
            httpParserStates.COMPLETE,
        )

        # Send headers and blank line, thus completing HTTP request
        assert self.http_server_port is not None
        self._conn.recv.return_value = CRLF.join([
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            CRLF,
        ])
        self.assert_data_queued(mock_server_connection, server)
        self.protocol_handler._run_once()
        server.flush.assert_called_once()

    def assert_tunnel_response(
            self, mock_server_connection: mock.Mock, server: mock.Mock,
    ) -> None:
        self.protocol_handler._run_once()
        self.assertTrue(
            cast(
                HttpProxyPlugin,
                self.protocol_handler.plugins['HttpProxyPlugin'],
            ).upstream is not None,
        )
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
        )
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.queue.assert_not_called()
        server.closed = False

        parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        parser.parse(self.protocol_handler.work.buffer[0].tobytes())
        self.assertEqual(parser.state, httpParserStates.COMPLETE)
        assert parser.code is not None
        self.assertEqual(int(parser.code), 200)

    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_http_tunnel(self, mock_server_connection: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True

        def has_buffer() -> bool:
            return cast(bool, server.queue.called)

        server.has_buffer.side_effect = has_buffer
        self.mock_selector.return_value.select.side_effect = [
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn,
                        fd=self._conn.fileno,
                        events=selectors.EVENT_READ,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn,
                        fd=self._conn.fileno,
                        events=0,
                        data=None,
                    ),
                    selectors.EVENT_WRITE,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn,
                        fd=self._conn.fileno,
                        events=selectors.EVENT_READ,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=server.connection,
                        fd=server.connection.fileno,
                        events=0,
                        data=None,
                    ),
                    selectors.EVENT_WRITE,
                ),
            ],
        ]

        assert self.http_server_port is not None
        self._conn.recv.return_value = CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            b'Proxy-Connection: Keep-Alive',
            CRLF,
        ])
        self.assert_tunnel_response(mock_server_connection, server)

        # Dispatch tunnel established response to client
        self.protocol_handler._run_once()
        self.assert_data_queued_to_server(server)

        self.protocol_handler._run_once()
        self.assertEqual(server.queue.call_count, 1)
        server.flush.assert_called_once()

    def test_proxy_connection_failed(self) -> None:
        self.mock_selector_for_client_read(self.mock_selector)
        self._conn.recv.return_value = CRLF.join([
            b'GET http://unknown.domain HTTP/1.1',
            b'Host: unknown.domain',
            CRLF,
        ])
        self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            ProxyConnectionFailed.RESPONSE_PKT,
        )

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_proxy_authentication_failed(
            self,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
    ) -> None:
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)
        flags = FlagParser.initialize(
            auth_code=base64.b64encode(b'user:pass'),
            threaded=True,
        )
        flags.plugins = Plugins.load([
            bytes_(PLUGIN_HTTP_PROXY),
            bytes_(PLUGIN_WEB_SERVER),
            bytes_(PLUGIN_PROXY_AUTH),
        ])
        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr), flags=flags,
        )
        self.protocol_handler.initialize()
        self._conn.recv.return_value = CRLF.join([
            b'GET http://abhinavsingh.com HTTP/1.1',
            b'Host: abhinavsingh.com',
            CRLF,
        ])
        self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            ProxyAuthenticationFailed.RESPONSE_PKT,
        )

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_authenticated_proxy_http_get(
            self, mock_server_connection: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
    ) -> None:
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)

        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0

        flags = FlagParser.initialize(
            auth_code=base64.b64encode(b'user:pass'),
            threaded=True,
        )
        flags.plugins = Plugins.load([
            bytes_(PLUGIN_HTTP_PROXY),
            bytes_(PLUGIN_WEB_SERVER),
        ])

        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr), flags=flags,
        )
        self.protocol_handler.initialize()
        assert self.http_server_port is not None

        self._conn.recv.return_value = b'GET http://localhost:%d HTTP/1.1' % self.http_server_port
        self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.INITIALIZED,
        )

        self._conn.recv.return_value = CRLF
        self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.LINE_RCVD,
        )

        assert self.http_server_port is not None
        self._conn.recv.return_value = CRLF.join([
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            CRLF,
        ])
        self.assert_data_queued(mock_server_connection, server)

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_authenticated_proxy_http_tunnel(
            self, mock_server_connection: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
    ) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read_read_server_write(
            mock_selector, server,
        )

        flags = FlagParser.initialize(
            auth_code=base64.b64encode(b'user:pass'),
            threaded=True,
        )
        flags.plugins = Plugins.load([
            bytes_(PLUGIN_HTTP_PROXY),
            bytes_(PLUGIN_WEB_SERVER),
        ])

        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr), flags=flags,
        )
        self.protocol_handler.initialize()

        assert self.http_server_port is not None
        self._conn.recv.return_value = CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            CRLF,
        ])
        self.assert_tunnel_response(mock_server_connection, server)
        self.protocol_handler.work.flush()
        self.assert_data_queued_to_server(server)

        self.protocol_handler._run_once()
        server.flush.assert_called_once()

    def mock_selector_for_client_read_read_server_write(
            self, mock_selector: mock.Mock, server: mock.Mock,
    ) -> None:
        mock_selector.return_value.select.side_effect = [
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn,
                        fd=self._conn.fileno,
                        events=selectors.EVENT_READ,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn,
                        fd=self._conn.fileno,
                        events=0,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=server.connection,
                        fd=server.connection.fileno,
                        events=0,
                        data=None,
                    ),
                    selectors.EVENT_WRITE,
                ),
            ],
        ]

    def assert_data_queued(
            self, mock_server_connection: mock.Mock, server: mock.Mock,
    ) -> None:
        self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.COMPLETE,
        )
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.closed = False
        assert self.http_server_port is not None
        pkt = CRLF.join([
            b'GET / HTTP/1.1',
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Via: 1.1 proxy.py v%s' % bytes_(__version__),
            CRLF,
        ])
        server.queue.assert_called_once()
        self.assertEqual(server.queue.call_args_list[0][0][0].tobytes(), pkt)
        server.buffer_size.return_value = len(pkt)

    def assert_data_queued_to_server(self, server: mock.Mock) -> None:
        assert self.http_server_port is not None
        self.assertEqual(
            self._conn.send.call_args[0][0],
            HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
        )

        pkt = CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            CRLF,
        ])

        self._conn.recv.return_value = pkt
        self.protocol_handler._run_once()

        server.queue.assert_called_once_with(pkt)
        server.buffer_size.return_value = len(pkt)
        server.flush.assert_not_called()

    def mock_selector_for_client_read(self, mock_selector: mock.Mock) -> None:
        mock_selector.return_value.select.return_value = [
            (
                selectors.SelectorKey(
                    fileobj=self._conn,
                    fd=self._conn.fileno,
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            ),
        ]
