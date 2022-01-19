# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import base64
import selectors
from typing import Any, cast

import pytest
from unittest import mock

from pytest_mock import MockerFixture

from proxy.http import HttpProtocolHandler, httpHeaders, HttpClientConnection
from proxy.http.proxy import HttpProxyPlugin
from proxy.common.flag import FlagParser
from proxy.http.parser import HttpParser, httpParserTypes, httpParserStates
from proxy.common.utils import bytes_
from proxy.common.plugins import Plugins
from proxy.common.version import __version__
from proxy.http.responses import (
    BAD_GATEWAY_RESPONSE_PKT, PROXY_AUTH_FAILED_RESPONSE_PKT,
    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT, BAD_REQUEST_RESPONSE_PKT,
)
from proxy.common.constants import (
    CRLF, PLUGIN_HTTP_PROXY, PLUGIN_PROXY_AUTH, PLUGIN_WEB_SERVER,
)
from ..test_assertions import Assertions


def mock_selector_for_client_read(self: Any) -> None:
    self.mock_selector.return_value.select.return_value = [
        (
            selectors.SelectorKey(
                fileobj=self._conn.fileno(),
                fd=self._conn.fileno(),
                events=selectors.EVENT_READ,
                data=None,
            ),
            selectors.EVENT_READ,
        ),
    ]


class TestHttpProtocolHandlerWithoutServerMock(Assertions):

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture) -> None:
        self.mock_fromfd = mocker.patch('socket.fromfd')
        self.mock_selector = mocker.patch('selectors.DefaultSelector')

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = self.mock_fromfd.return_value

        self.http_server_port = 65535
        self.flags = FlagParser.initialize(threaded=True)
        self.flags.plugins = Plugins.load([
            bytes_(PLUGIN_HTTP_PROXY),
            bytes_(PLUGIN_WEB_SERVER),
        ])

        self.protocol_handler = HttpProtocolHandler(
            HttpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_connection_failed(self) -> None:
        mock_selector_for_client_read(self)
        self._conn.recv.return_value = CRLF.join([
            b'GET http://unknown.domain HTTP/1.1',
            b'Host: unknown.domain',
            CRLF,
        ])
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            BAD_GATEWAY_RESPONSE_PKT,
        )

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_authentication_failed(self) -> None:
        self._conn = self.mock_fromfd.return_value
        mock_selector_for_client_read(self)
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
            HttpClientConnection(self._conn, self._addr), flags=flags,
        )
        self.protocol_handler.initialize()
        self._conn.recv.return_value = CRLF.join([
            b'GET http://abhinavsingh.com HTTP/1.1',
            b'Host: abhinavsingh.com',
            CRLF,
        ])
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            PROXY_AUTH_FAILED_RESPONSE_PKT,
        )

    @pytest.mark.asyncio
    async def test_proxy_bails_out_for_unknown_schemes(self) -> None:
        mock_selector_for_client_read(self)
        self._conn.recv.return_value = CRLF.join([
            b'REQMOD icap://icap-server.net/server?arg=87 ICAP/1.0',
            b'Host: icap-server.net',
            CRLF,
        ])
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            BAD_REQUEST_RESPONSE_PKT,
        )

    @pytest.mark.asyncio
    async def test_proxy_bails_out_for_sip_request_lines(self) -> None:
        mock_selector_for_client_read(self)
        self._conn.recv.return_value = CRLF.join([
            b'OPTIONS sip:nm SIP/2.0',
            b'Accept: application/sdp',
            CRLF,
        ])
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            BAD_REQUEST_RESPONSE_PKT,
        )


class TestHttpProtocolHandler(Assertions):

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture) -> None:
        self.mock_fromfd = mocker.patch('socket.fromfd')
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_server_connection = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
        )

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = self.mock_fromfd.return_value

        self.http_server_port = 65535
        self.flags = FlagParser.initialize(threaded=True)
        self.flags.plugins = Plugins.load([
            bytes_(PLUGIN_HTTP_PROXY),
            bytes_(PLUGIN_WEB_SERVER),
        ])

        self.protocol_handler = HttpProtocolHandler(
            HttpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_http_get(self) -> None:
        server = self.mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0

        self.mock_selector_for_client_read_and_server_write(server)

        # Send request line
        assert self.http_server_port is not None
        self._conn.recv.return_value = (
            b'GET http://localhost:%d HTTP/1.1' %
            self.http_server_port
        ) + CRLF

        await self.protocol_handler._run_once()

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
        await self.assert_data_queued(server)
        await self.protocol_handler._run_once()
        server.flush.assert_called_once()

    async def assert_tunnel_response(
            self,
            server: mock.Mock,
    ) -> None:
        await self.protocol_handler._run_once()
        self.assertTrue(
            cast(
                HttpProxyPlugin,
                self.protocol_handler.plugin,
            ).upstream is not None,
        )
        self.assertEqual(
            self.protocol_handler.work.buffer[0],
            PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
        )
        self.mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.queue.assert_not_called()
        server.closed = False

        parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
        parser.parse(self.protocol_handler.work.buffer[0].tobytes())
        self.assertEqual(parser.state, httpParserStates.COMPLETE)
        assert parser.code is not None
        self.assertEqual(int(parser.code), 200)

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_http_tunnel(self) -> None:
        server = self.mock_server_connection.return_value
        server.connect.return_value = True

        def has_buffer() -> bool:
            return cast(bool, server.queue.called)

        server.has_buffer.side_effect = has_buffer
        self.mock_selector.return_value.select.side_effect = [
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn.fileno(),
                        fd=self._conn.fileno(),
                        events=selectors.EVENT_READ,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn.fileno(),
                        fd=self._conn.fileno(),
                        events=0,
                        data=None,
                    ),
                    selectors.EVENT_WRITE,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn.fileno(),
                        fd=self._conn.fileno(),
                        events=selectors.EVENT_READ,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=server.connection.fileno(),
                        fd=server.connection.fileno(),
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
        await self.assert_tunnel_response(server)

        # Dispatch tunnel established response to client
        await self.protocol_handler._run_once()
        await self.assert_data_queued_to_server(server)

        await self.protocol_handler._run_once()
        self.assertEqual(server.queue.call_count, 1)
        server.flush.assert_called_once()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_authenticated_proxy_http_get(self) -> None:
        self._conn = self.mock_fromfd.return_value
        mock_selector_for_client_read(self)

        server = self.mock_server_connection.return_value
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
            HttpClientConnection(self._conn, self._addr), flags=flags,
        )
        self.protocol_handler.initialize()
        assert self.http_server_port is not None

        self._conn.recv.return_value = b'GET http://localhost:%d HTTP/1.1' % self.http_server_port
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.INITIALIZED,
        )

        self._conn.recv.return_value = CRLF
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.LINE_RCVD,
        )

        assert self.http_server_port is not None
        self._conn.recv.return_value = CRLF.join([
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            httpHeaders.PROXY_CONNECTION + b': Keep-Alive',
            httpHeaders.PROXY_AUTHORIZATION + b': Basic dXNlcjpwYXNz',
            CRLF,
        ])
        await self.assert_data_queued(server)

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_authenticated_proxy_http_tunnel(self) -> None:
        server = self.mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0
        self._conn = self.mock_fromfd.return_value
        self.mock_selector_for_client_read_and_server_write(server)

        flags = FlagParser.initialize(
            auth_code=base64.b64encode(b'user:pass'),
            threaded=True,
        )
        flags.plugins = Plugins.load([
            bytes_(PLUGIN_HTTP_PROXY),
            bytes_(PLUGIN_WEB_SERVER),
        ])

        self.protocol_handler = HttpProtocolHandler(
            HttpClientConnection(self._conn, self._addr), flags=flags,
        )
        self.protocol_handler.initialize()

        assert self.http_server_port is not None
        self._conn.recv.return_value = CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            httpHeaders.PROXY_CONNECTION + b': Keep-Alive',
            httpHeaders.PROXY_AUTHORIZATION + b': Basic dXNlcjpwYXNz',
            CRLF,
        ])
        await self.assert_tunnel_response(server)
        self.protocol_handler.work.flush()
        await self.assert_data_queued_to_server(server)

        await self.protocol_handler._run_once()
        server.flush.assert_called_once()

    def mock_selector_for_client_read_and_server_write(
            self, server: mock.Mock,
    ) -> None:
        self.mock_selector.return_value.select.side_effect = [
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn.fileno(),
                        fd=self._conn.fileno(),
                        events=selectors.EVENT_READ,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=self._conn.fileno(),
                        fd=self._conn.fileno(),
                        events=0,
                        data=None,
                    ),
                    selectors.EVENT_READ,
                ),
            ],
            [
                (
                    selectors.SelectorKey(
                        fileobj=server.connection.fileno(),
                        fd=server.connection.fileno(),
                        events=0,
                        data=None,
                    ),
                    selectors.EVENT_WRITE,
                ),
            ],
        ]

    async def assert_data_queued(
            self, server: mock.Mock,
    ) -> None:
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.COMPLETE,
        )
        self.mock_server_connection.assert_called_once()
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

    async def assert_data_queued_to_server(self, server: mock.Mock) -> None:
        assert self.http_server_port is not None
        self.assertEqual(
            self._conn.send.call_args[0][0],
            PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
        )

        pkt = CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % bytes_(__version__),
            CRLF,
        ])

        self._conn.recv.return_value = pkt
        await self.protocol_handler._run_once()

        server.queue.assert_called_once_with(pkt)
        server.buffer_size.return_value = len(pkt)
        server.flush.assert_not_called()
