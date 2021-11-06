# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import uuid
import unittest
import socket
import ssl
import selectors

from typing import Any
from unittest import mock
from proxy.common.constants import DEFAULT_CA_FILE

from proxy.core.connection import TcpClientConnection, TcpServerConnection
from proxy.http.handler import HttpProtocolHandler
from proxy.http.proxy import HttpProxyPlugin
from proxy.http.methods import httpMethods
from proxy.common.utils import build_http_request, bytes_
from proxy.proxy import Proxy


class TestHttpProxyTlsInterception(unittest.TestCase):

    @mock.patch('ssl.wrap_socket')
    @mock.patch('ssl.create_default_context')
    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    @mock.patch('proxy.http.proxy.server.gen_public_key')
    @mock.patch('proxy.http.proxy.server.gen_csr')
    @mock.patch('proxy.http.proxy.server.sign_csr')
    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_e2e(
            self,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
            mock_sign_csr: mock.Mock,
            mock_gen_csr: mock.Mock,
            mock_gen_public_key: mock.Mock,
            mock_server_conn: mock.Mock,
            mock_ssl_context: mock.Mock,
            mock_ssl_wrap: mock.Mock,
    ) -> None:
        host, port = uuid.uuid4().hex, 443
        netloc = '{0}:{1}'.format(host, port)

        self.mock_fromfd = mock_fromfd
        self.mock_selector = mock_selector
        self.mock_sign_csr = mock_sign_csr
        self.mock_gen_csr = mock_gen_csr
        self.mock_gen_public_key = mock_gen_public_key
        self.mock_server_conn = mock_server_conn
        self.mock_ssl_context = mock_ssl_context
        self.mock_ssl_wrap = mock_ssl_wrap

        self.mock_sign_csr.return_value = True
        self.mock_gen_csr.return_value = True
        self.mock_gen_public_key.return_value = True

        ssl_connection = mock.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_context.return_value.wrap_socket.return_value = ssl_connection
        self.mock_ssl_wrap.return_value = mock.MagicMock(spec=ssl.SSLSocket)
        plain_connection = mock.MagicMock(spec=socket.socket)

        def mock_connection() -> Any:
            if self.mock_ssl_context.return_value.wrap_socket.called:
                return ssl_connection
            return plain_connection

        # Do not mock the original wrap method
        self.mock_server_conn.return_value.wrap.side_effect = \
            lambda x, y: TcpServerConnection.wrap(
                self.mock_server_conn.return_value, x, y,
            )

        type(self.mock_server_conn.return_value).connection = \
            mock.PropertyMock(side_effect=mock_connection)

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.flags = Proxy.initialize(
            ca_cert_file='ca-cert.pem',
            ca_key_file='ca-key.pem',
            ca_signing_key_file='ca-signing-key.pem',
        )
        self.plugin = mock.MagicMock()
        self.proxy_plugin = mock.MagicMock()
        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [self.plugin, HttpProxyPlugin],
            b'HttpProxyBasePlugin': [self.proxy_plugin],
        }
        self._conn = mock_fromfd.return_value
        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

        self.plugin.assert_called()
        self.assertEqual(self.plugin.call_args[0][1], self.flags)
        self.assertEqual(self.plugin.call_args[0][2].connection, self._conn)
        self.proxy_plugin.assert_called()
        self.assertEqual(self.proxy_plugin.call_args[0][1], self.flags)
        self.assertEqual(
            self.proxy_plugin.call_args[0][2].connection,
            self._conn,
        )

        connect_request = build_http_request(
            httpMethods.CONNECT, bytes_(netloc),
            headers={
                b'Host': bytes_(netloc),
            },
        )
        self._conn.recv.return_value = connect_request

        # Prepare mocked HttpProtocolHandlerPlugin
        self.plugin.return_value.get_descriptors.return_value = ([], [])
        self.plugin.return_value.write_to_descriptors.return_value = False
        self.plugin.return_value.read_from_descriptors.return_value = False
        self.plugin.return_value.on_client_data.side_effect = lambda raw: raw
        self.plugin.return_value.on_request_complete.return_value = False
        self.plugin.return_value.on_response_chunk.side_effect = lambda chunk: chunk
        self.plugin.return_value.on_client_connection_close.return_value = None

        # Prepare mocked HttpProxyBasePlugin
        self.proxy_plugin.return_value.write_to_descriptors.return_value = False
        self.proxy_plugin.return_value.read_from_descriptors.return_value = False
        self.proxy_plugin.return_value.before_upstream_connection.side_effect = lambda r: r
        self.proxy_plugin.return_value.handle_client_request.side_effect = lambda r: r
        self.proxy_plugin.return_value.resolve_dns.return_value = None, None

        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn,
                    fd=self._conn.fileno,
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]

        self.protocol_handler._run_once()

        # Assert our mocked plugins invocations
        self.plugin.return_value.get_descriptors.assert_called()
        self.plugin.return_value.write_to_descriptors.assert_called_with([])
        self.plugin.return_value.on_client_data.assert_called_with(
            connect_request,
        )
        self.plugin.return_value.on_request_complete.assert_called()
        self.plugin.return_value.read_from_descriptors.assert_called_with([
            self._conn,
        ])
        self.proxy_plugin.return_value.before_upstream_connection.assert_called()
        self.proxy_plugin.return_value.handle_client_request.assert_called()

        self.mock_server_conn.assert_called_with(host, port)
        self.mock_server_conn.return_value.connection.setblocking.assert_called_with(
            False,
        )

        self.mock_ssl_context.assert_called_with(
            ssl.Purpose.SERVER_AUTH, cafile=str(DEFAULT_CA_FILE),
        )
        # self.assertEqual(self.mock_ssl_context.return_value.options,
        # ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 |
        # ssl.OP_NO_TLSv1_1)
        self.assertEqual(plain_connection.setblocking.call_count, 2)
        self.mock_ssl_context.return_value.wrap_socket.assert_called_with(
            plain_connection, server_hostname=host,
        )
        self.assertEqual(self.mock_sign_csr.call_count, 1)
        self.assertEqual(self.mock_gen_csr.call_count, 1)
        self.assertEqual(self.mock_gen_public_key.call_count, 1)
        self.assertEqual(ssl_connection.setblocking.call_count, 1)
        self.assertEqual(
            self.mock_server_conn.return_value._conn,
            ssl_connection,
        )
        self._conn.send.assert_called_with(
            HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT,
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
            self.protocol_handler.client.connection,
            self.mock_ssl_wrap.return_value,
        )

        # Assert connection references for all other plugins is updated
        self.assertEqual(
            self.plugin.return_value.client._conn,
            self.mock_ssl_wrap.return_value,
        )
        self.assertEqual(
            self.proxy_plugin.return_value.client._conn,
            self.mock_ssl_wrap.return_value,
        )
