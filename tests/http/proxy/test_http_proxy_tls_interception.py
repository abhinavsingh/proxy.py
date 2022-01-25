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
import uuid
import socket
import selectors
from typing import Any, TypeVar

import pytest
from unittest import mock

from pytest_mock import MockerFixture

from proxy.http import HttpProtocolHandler, HttpClientConnection, httpMethods
from proxy.http.proxy import HttpProxyPlugin
from proxy.common.flag import FlagParser
from proxy.http.parser import HttpParser
from proxy.common.utils import (
    bytes_, build_http_request, tls_interception_enabled,
)
from proxy.http.responses import PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT
from proxy.core.connection import TcpServerConnection
from proxy.common.constants import DEFAULT_CA_FILE
from ...test_assertions import Assertions


class TestHttpProxyTlsInterception(Assertions):

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_e2e(self, mocker: MockerFixture) -> None:
        host, port = uuid.uuid4().hex, 443
        netloc = '{0}:{1}'.format(host, port)

        self.mock_fromfd = mocker.patch('socket.fromfd')
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_sign_csr = mocker.patch('proxy.http.proxy.server.sign_csr')
        self.mock_gen_csr = mocker.patch('proxy.http.proxy.server.gen_csr')
        self.mock_gen_public_key = mocker.patch(
            'proxy.http.proxy.server.gen_public_key',
        )
        self.mock_server_conn = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
        )
        self.mock_sign_csr.return_value = True
        self.mock_gen_csr.return_value = True
        self.mock_gen_public_key.return_value = True

        # Used for server side wrapping
        self.mock_ssl_context = mocker.patch('ssl.create_default_context')
        upstream_tls_sock = mock.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_context.return_value.wrap_socket.return_value = upstream_tls_sock

        # Used for client wrapping
        self.mock_ssl_wrap = mocker.patch('ssl.wrap_socket')
        client_tls_sock = mock.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_wrap.return_value = client_tls_sock

        plain_connection = mock.MagicMock(spec=socket.socket)

        def mock_connection() -> Any:
            if self.mock_ssl_context.return_value.wrap_socket.called:
                return upstream_tls_sock
            return plain_connection

        # Do not mock the original wrap method
        self.mock_server_conn.return_value.wrap.side_effect = \
            lambda x, y, as_non_blocking: TcpServerConnection.wrap(
                self.mock_server_conn.return_value, x, y, as_non_blocking=as_non_blocking,
            )

        type(self.mock_server_conn.return_value).connection = \
            mock.PropertyMock(side_effect=mock_connection)

        type(self.mock_server_conn.return_value).closed = \
            mock.PropertyMock(return_value=False)

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.flags = FlagParser.initialize(
            ca_cert_file='ca-cert.pem',
            ca_key_file='ca-key.pem',
            ca_signing_key_file='ca-signing-key.pem',
            threaded=True,
        )
        self.assertTrue(tls_interception_enabled(self.flags))
        # In this test we enable a mock http protocol handler plugin
        # and a mock http proxy plugin.  Internally, http protocol
        # handler will only initialize proxy plugin as we'll never
        # make any other request.
        self.plugin = mock.MagicMock()
        self.proxy_plugin = mock.MagicMock()
        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [self.plugin, HttpProxyPlugin],
            b'HttpProxyBasePlugin': [self.proxy_plugin],
        }
        self._conn = self.mock_fromfd.return_value
        self.protocol_handler = HttpProtocolHandler(
            HttpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

        self.plugin.assert_not_called()
        self.proxy_plugin.assert_not_called()

        # Mock a CONNECT request followed by a GET request
        # from client connection
        headers = {
            b'Host': bytes_(netloc),
        }
        connect_request = build_http_request(
            httpMethods.CONNECT, bytes_(netloc),
            headers=headers,
        )
        self._conn.recv.return_value = connect_request
        get_request = build_http_request(
            httpMethods.GET, b'/',
            headers=headers,
        )
        client_tls_sock.recv.return_value = get_request

        T = TypeVar('T')    # noqa: N806

        async def asyncReturn(val: T) -> T:
            return val

        # Prepare mocked HttpProxyBasePlugin
        # 1. Mock descriptor mixin methods
        #
        # NOTE: We need multiple async result otherwise
        # we will end up with cannot await on already
        # awaited coroutine.
        self.proxy_plugin.return_value.get_descriptors.side_effect = \
            [asyncReturn(([], [])), asyncReturn(([], []))]
        self.proxy_plugin.return_value.write_to_descriptors.side_effect = \
            [asyncReturn(False), asyncReturn(False)]
        self.proxy_plugin.return_value.read_from_descriptors.side_effect = \
            [asyncReturn(False), asyncReturn(False)]
        # 2. Mock plugin lifecycle methods
        self.proxy_plugin.return_value.resolve_dns.return_value = None, None
        self.proxy_plugin.return_value.before_upstream_connection.side_effect = lambda r: r
        self.proxy_plugin.return_value.handle_client_data.side_effect = lambda r: r
        self.proxy_plugin.return_value.handle_client_request.side_effect = lambda r: r
        self.proxy_plugin.return_value.handle_upstream_chunk.side_effect = lambda r: r
        self.proxy_plugin.return_value.on_upstream_connection_close.return_value = None
        self.proxy_plugin.return_value.on_access_log.side_effect = lambda r: r
        self.proxy_plugin.return_value.do_intercept.return_value = True

        self.mock_selector.return_value.select.side_effect = [
            # Trigger read on plain socket
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
            # Trigger read on encrypted socket
            [(
                selectors.SelectorKey(
                    fileobj=client_tls_sock.fileno(),
                    fd=client_tls_sock.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]

        await self.protocol_handler._run_once()

        # Assert correct plugin was initialized
        self.plugin.assert_not_called()
        self.proxy_plugin.assert_called_once()
        self.assertEqual(self.proxy_plugin.call_args[0][1], self.flags)
        # Actual call arg must be `_conn` object
        # but because internally the reference is updated
        # we assert it against `mock_ssl_wrap` which is
        # called during proxy plugin initialization
        # for interception
        self.assertEqual(
            self.proxy_plugin.call_args[0][2].connection,
            client_tls_sock,
        )

        # Invoked lifecycle callbacks
        self.proxy_plugin.return_value.resolve_dns.assert_called_once_with(
            host, port,
        )
        self.proxy_plugin.return_value.before_upstream_connection.assert_called()
        self.proxy_plugin.return_value.handle_client_request.assert_called_once()
        self.proxy_plugin.return_value.do_intercept.assert_called_once()
        # All the invoked lifecycle callbacks will receive the CONNECT request
        # packet with / as the path
        callback_request: HttpParser = \
            self.proxy_plugin.return_value.before_upstream_connection.call_args_list[0][0][0]
        callback_request1: HttpParser = \
            self.proxy_plugin.return_value.handle_client_request.call_args_list[0][0][0]
        callback_request2: HttpParser = \
            self.proxy_plugin.return_value.do_intercept.call_args_list[0][0][0]
        self.assertEqual(callback_request.host, bytes_(host))
        self.assertEqual(callback_request.port, 443)
        self.assertEqual(callback_request.header(b'Host'), headers[b'Host'])
        assert callback_request._url
        self.assertEqual(callback_request._url.remainder, None)
        self.assertEqual(callback_request.method, httpMethods.CONNECT)
        self.assertEqual(callback_request.is_https_tunnel, True)
        self.assertEqual(callback_request.build(), callback_request1.build())
        self.assertEqual(callback_request.build(), callback_request2.build())
        # Lifecycle callbacks not invoked
        self.proxy_plugin.return_value.handle_client_data.assert_not_called()
        self.proxy_plugin.return_value.handle_upstream_chunk.assert_not_called()
        self.proxy_plugin.return_value.on_upstream_connection_close.assert_not_called()
        self.proxy_plugin.return_value.on_access_log.assert_not_called()

        self.mock_server_conn.assert_called_with(host, port)
        self.mock_server_conn.return_value.connection.setblocking.assert_called_with(
            False,
        )

        self.mock_ssl_context.assert_called_with(
            ssl.Purpose.SERVER_AUTH, cafile=str(DEFAULT_CA_FILE),
        )
        self.assertEqual(plain_connection.setblocking.call_count, 2)
        self.mock_ssl_context.return_value.wrap_socket.assert_called_with(
            plain_connection, server_hostname=host,
        )
        self.assertEqual(self.mock_sign_csr.call_count, 1)
        self.assertEqual(self.mock_gen_csr.call_count, 1)
        self.assertEqual(self.mock_gen_public_key.call_count, 1)
        self.assertEqual(upstream_tls_sock.setblocking.call_count, 1)
        self.assertEqual(
            self.mock_server_conn.return_value._conn,
            upstream_tls_sock,
        )
        self._conn.send.assert_called_with(
            PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
        )
        assert self.flags.ca_cert_dir is not None
        self.mock_ssl_wrap.assert_called_with(
            self._conn,
            server_side=True,
            keyfile=self.flags.ca_signing_key_file,
            certfile=HttpProxyPlugin.generated_cert_file_path(
                self.flags.ca_cert_dir, host,
            ),
            ssl_version=ssl.PROTOCOL_TLS,
        )
        self.assertEqual(self._conn.setblocking.call_count, 2)
        self.assertEqual(
            self.protocol_handler.work.connection,
            client_tls_sock,
        )

        # Assert connection references for all other plugins is updated
        self.assertEqual(
            self.proxy_plugin.return_value.client._conn,
            client_tls_sock,
        )

        # Now process the GET request
        await self.protocol_handler._run_once()
        self.plugin.assert_not_called()
        self.proxy_plugin.assert_called_once()

        # Lifecycle callbacks still not invoked
        self.proxy_plugin.return_value.handle_client_data.assert_not_called()
        self.proxy_plugin.return_value.handle_upstream_chunk.assert_not_called()
        self.proxy_plugin.return_value.on_upstream_connection_close.assert_not_called()
        self.proxy_plugin.return_value.on_access_log.assert_not_called()
        # Only handle client request lifecycle must be called again
        self.proxy_plugin.return_value.resolve_dns.assert_called_once_with(
            host, port,
        )
        self.proxy_plugin.return_value.before_upstream_connection.assert_called()
        self.assertEqual(
            self.proxy_plugin.return_value.handle_client_request.call_count,
            2,
        )
        self.proxy_plugin.return_value.do_intercept.assert_called_once()

        callback_request = \
            self.proxy_plugin.return_value.handle_client_request.call_args_list[1][0][0]
        self.assertEqual(callback_request.host, None)
        self.assertEqual(callback_request.port, 80)
        self.assertEqual(callback_request.header(b'Host'), headers[b'Host'])
        assert callback_request._url
        self.assertEqual(callback_request._url.remainder, b'/')
        self.assertEqual(callback_request.method, httpMethods.GET)
        self.assertEqual(callback_request.is_https_tunnel, False)
