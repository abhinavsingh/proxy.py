# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import ssl
import gzip
import socket
import selectors
from typing import Any, cast

import pytest

from pytest_mock import MockerFixture

from proxy.http import HttpProtocolHandler, HttpClientConnection, httpMethods
from proxy.http.proxy import HttpProxyPlugin
from proxy.common.flag import FlagParser
from proxy.http.parser import HttpParser, httpParserTypes
from proxy.common.utils import bytes_, build_http_request
from proxy.http.responses import (
    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT, okResponse,
)
from proxy.core.connection import TcpServerConnection
from .utils import get_plugin_by_test_name
from ..test_assertions import Assertions


class TestHttpProxyPluginExamplesWithTlsInterception(Assertions):

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, request: Any, mocker: MockerFixture) -> None:
        self.mock_socket_dup = mocker.patch('socket.dup')
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_sign_csr = mocker.patch('proxy.http.proxy.server.sign_csr')
        self.mock_gen_csr = mocker.patch('proxy.http.proxy.server.gen_csr')
        self.mock_gen_public_key = mocker.patch(
            'proxy.http.proxy.server.gen_public_key',
        )
        self.mock_server_conn = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
        )
        self.mock_ssl_context = mocker.patch('ssl.create_default_context')
        self.mock_ssl_wrap = mocker.patch('ssl.SSLContext')

        self.mock_sign_csr.return_value = True
        self.mock_gen_csr.return_value = True
        self.mock_gen_public_key.return_value = True

        self.fileno = 10
        self.mock_socket_dup.side_effect = lambda fd: fd

        self._addr = ('127.0.0.1', 54382)
        self.flags = FlagParser.initialize(
            ca_cert_file='ca-cert.pem',
            ca_key_file='ca-key.pem',
            ca_signing_key_file='ca-signing-key.pem',
            threaded=True,
        )
        self.plugin = mocker.MagicMock()

        plugin = get_plugin_by_test_name(request.param)

        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
            b'HttpProxyBasePlugin': [plugin],
        }
        self._conn = mocker.MagicMock(spec=socket.socket)

        self.protocol_handler = HttpProtocolHandler(
            HttpClientConnection(self._conn, self._addr), flags=self.flags,
        )
        self.protocol_handler.initialize()

        self.server = self.mock_server_conn.return_value

        self.server_ssl_connection = mocker.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_context.return_value.wrap_socket.return_value = self.server_ssl_connection
        self.client_ssl_connection = mocker.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_wrap.return_value.wrap_socket.return_value = self.client_ssl_connection

        def has_buffer() -> bool:
            return cast(bool, self.server.queue.called)

        def closed() -> bool:
            return not self.server.connect.called

        def mock_connection() -> Any:
            if self.mock_ssl_context.return_value.wrap_socket.called:
                return self.server_ssl_connection
            return self._conn

        # Do not mock the original wrap method
        self.server.wrap.side_effect = \
            lambda x, y, as_non_blocking: TcpServerConnection.wrap(
                self.server, x, y, as_non_blocking=as_non_blocking,
            )

        self.server.has_buffer.side_effect = has_buffer
        type(self.server).closed = mocker.PropertyMock(side_effect=closed)
        type(
            self.server,
        ).connection = mocker.PropertyMock(
            side_effect=mock_connection,
        )

        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
            [(
                selectors.SelectorKey(
                    fileobj=self.client_ssl_connection.fileno(),
                    fd=self.client_ssl_connection.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
            [(
                selectors.SelectorKey(
                    fileobj=self.server_ssl_connection.fileno(),
                    fd=self.server_ssl_connection.fileno(),
                    events=selectors.EVENT_WRITE,
                    data=None,
                ),
                selectors.EVENT_WRITE,
            )],
            [(
                selectors.SelectorKey(
                    fileobj=self.server_ssl_connection.fileno(),
                    fd=self.server_ssl_connection.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]

        # Connect
        def send(raw: bytes) -> int:
            return len(raw)

        self._conn.send.side_effect = send
        self._conn.recv.return_value = build_http_request(
            httpMethods.CONNECT,
            b'uni.corn:443',
            no_ua=True,
        )

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        '_setUp',
        (
            ('test_modify_post_data_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_modify_post_data_plugin(self) -> None:
        await self.protocol_handler._run_once()

        self.assertEqual(self.mock_sign_csr.call_count, 1)
        self.assertEqual(self.mock_gen_csr.call_count, 1)
        self.assertEqual(self.mock_gen_public_key.call_count, 1)

        self.mock_server_conn.assert_called_once_with('uni.corn', 443)
        self.server.connect.assert_called()
        self.assertEqual(
            self.protocol_handler.work.connection,
            self.client_ssl_connection,
        )
        self.assertEqual(self.server.connection, self.server_ssl_connection)
        self._conn.send.assert_called_with(
            PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
        )
        self.assertFalse(self.protocol_handler.work.has_buffer())

        #
        original = b'{"key": "value"}'
        modified = b'{"key": "modified"}'
        self.client_ssl_connection.recv.return_value = build_http_request(
            b'POST', b'/',
            headers={
                b'Host': b'uni.corn',
                b'Content-Length': bytes_(len(original)),
                b'Content-Type': b'application/x-www-form-urlencoded',
            },
            body=original,
            no_ua=True,
        )
        await self.protocol_handler._run_once()
        self.server.queue.assert_called_once()
        # pkt = build_http_request(
        #     b'POST', b'/',
        #     headers={
        #         b'Host': b'uni.corn',
        #         b'Content-Length': bytes_(len(modified)),
        #         b'Content-Type': b'application/json',
        #     },
        #     body=modified,
        # )
        response = HttpParser.response(
            self.server.queue.call_args_list[0][0][0].tobytes(),
        )
        self.assertEqual(response.body, modified)

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        '_setUp',
        (
            ('test_man_in_the_middle_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_man_in_the_middle_plugin(self) -> None:
        await self.protocol_handler._run_once()

        self.assertEqual(self.mock_sign_csr.call_count, 1)
        self.assertEqual(self.mock_gen_csr.call_count, 1)
        self.assertEqual(self.mock_gen_public_key.call_count, 1)

        self.mock_server_conn.assert_called_once_with('uni.corn', 443)
        self.server.connect.assert_called()
        self.assertEqual(
            self.protocol_handler.work.connection,
            self.client_ssl_connection,
        )
        self.assertEqual(self.server.connection, self.server_ssl_connection)
        self._conn.send.assert_called_with(
            PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
        )
        self.assertFalse(self.protocol_handler.work.has_buffer())
        #
        request = build_http_request(
            b'GET', b'/',
            headers={
                b'Host': b'uni.corn',
            },
            no_ua=True,
        )
        self.client_ssl_connection.recv.return_value = request

        # Client read
        await self.protocol_handler._run_once()
        self.server.queue.assert_called_once_with(request)

        # Server write
        await self.protocol_handler._run_once()
        self.server.flush.assert_called_once()

        # Server read
        self.server.recv.return_value = okResponse(
            content=b'Original Response From Upstream',
        )
        await self.protocol_handler._run_once()
        response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        response.parse(self.protocol_handler.work.buffer[0])
        assert response.body
        self.assertEqual(
            gzip.decompress(response.body),
            b'Hello from man in the middle',
        )
