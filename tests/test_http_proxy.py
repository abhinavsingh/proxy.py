# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
import selectors
from unittest import mock

from proxy.common.flags import Flags
from proxy.http.proxy import HttpProxyPlugin
from proxy.http.handler import ProtocolHandler
from proxy.http.exception import HttpProtocolException
from proxy.common.utils import build_http_request


class TestHttpProxyPlugin(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self,
              mock_fromfd: mock.Mock,
              mock_selector: mock.Mock) -> None:
        self.mock_fromfd = mock_fromfd
        self.mock_selector = mock_selector

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.flags = Flags()
        self.plugin = mock.MagicMock()
        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
            b'HttpProxyBasePlugin': [self.plugin]
        }
        self._conn = mock_fromfd.return_value
        self.protocol_handler = ProtocolHandler(
            self.fileno, self._addr, flags=self.flags)
        self.protocol_handler.initialize()

    def test_proxy_plugin_initialized(self) -> None:
        self.plugin.assert_called()

    @mock.patch('proxy.http.proxy.TcpServerConnection')
    def test_proxy_plugin_on_and_before_upstream_connection(
            self,
            mock_server_conn: mock.Mock) -> None:
        self.plugin.return_value.before_upstream_connection.side_effect = lambda r: r
        self.plugin.return_value.handle_client_request.side_effect = lambda r: r

        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://upstream.host/not-found.html',
            headers={
                b'Host': b'upstream.host'
            })
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]

        self.protocol_handler.run_once()
        mock_server_conn.assert_called_with('upstream.host', 80)
        self.plugin.return_value.before_upstream_connection.assert_called()
        self.plugin.return_value.handle_client_request.assert_called()

    @mock.patch('proxy.http.proxy.TcpServerConnection')
    def test_proxy_plugin_before_upstream_connection_can_teardown(
            self,
            mock_server_conn: mock.Mock) -> None:
        self.plugin.return_value.before_upstream_connection.side_effect = HttpProtocolException()

        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://upstream.host/not-found.html',
            headers={
                b'Host': b'upstream.host'
            })
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]

        self.protocol_handler.run_once()
        self.plugin.return_value.before_upstream_connection.assert_called()
        mock_server_conn.assert_not_called()
