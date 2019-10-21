# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import tempfile
import unittest
import selectors
from unittest import mock

from proxy.main import load_plugins
from proxy.flags import Flags
from proxy.protocol_handler import ProtocolHandler
from proxy.http_parser import httpParserStates
from proxy.utils import build_http_response, build_http_request, bytes_, text_
from proxy.constants import CRLF, PROXY_PY_DIR
from proxy.web_server import HttpWebServerPlugin


class TestWebServerPlugin(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = mock_fromfd.return_value
        self.mock_selector = mock_selector
        self.flags = Flags()
        self.flags.plugins = load_plugins(
            b'proxy.http_proxy.HttpProxyPlugin,proxy.web_server.HttpWebServerPlugin')
        self.protocol_handler = ProtocolHandler(
            self.fileno, self._addr, flags=self.flags)
        self.protocol_handler.initialize()

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_pac_file_served_from_disk(
            self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        pac_file = os.path.join(os.path.dirname(PROXY_PY_DIR), 'helper', 'proxy.pac')
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)
        self.init_and_make_pac_file_request(pac_file)
        self.protocol_handler.run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.COMPLETE)
        with open(pac_file, 'rb') as f:
            self._conn.send.called_once_with(build_http_response(
                200, reason=b'OK', headers={
                    b'Content-Type': b'application/x-ns-proxy-autoconfig',
                    b'Connection': b'close'
                }, body=f.read()
            ))

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_pac_file_served_from_buffer(
            self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)
        pac_file_content = b'function FindProxyForURL(url, host) { return "PROXY localhost:8899; DIRECT"; }'
        self.init_and_make_pac_file_request(text_(pac_file_content))
        self.protocol_handler.run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.COMPLETE)
        self._conn.send.called_once_with(build_http_response(
            200, reason=b'OK', headers={
                b'Content-Type': b'application/x-ns-proxy-autoconfig',
                b'Connection': b'close'
            }, body=pac_file_content
        ))

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_default_web_server_returns_404(
            self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        mock_selector.return_value.select.return_value = [(
            selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ), ]
        flags = Flags()
        flags.plugins = load_plugins(
            b'proxy.http_proxy.HttpProxyPlugin,proxy.web_server.HttpWebServerPlugin')
        self.protocol_handler = ProtocolHandler(
            self.fileno, self._addr, flags=flags)
        self.protocol_handler.initialize()
        self._conn.recv.return_value = CRLF.join([
            b'GET /hello HTTP/1.1',
            CRLF,
        ])
        self.protocol_handler.run_once()
        self.assertEqual(
            self.protocol_handler.request.state,
            httpParserStates.COMPLETE)
        self.assertEqual(
            self.protocol_handler.client.buffer,
            HttpWebServerPlugin.DEFAULT_404_RESPONSE)

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_static_web_server_serves(
            self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        # Setup a static directory
        static_server_dir = os.path.join(tempfile.gettempdir(), 'static')
        index_file_path = os.path.join(static_server_dir, 'index.html')
        html_file_content = b'''
        <html>
        <head></head>
        <body></body>
        </html>
        '''
        os.makedirs(static_server_dir, exist_ok=True)
        with open(index_file_path, 'wb') as f:
            f.write(html_file_content)

        self._conn = mock_fromfd.return_value
        self._conn.recv.return_value = build_http_request(b'GET', b'/index.html')

        mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)],
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_WRITE,
                data=None), selectors.EVENT_WRITE)], ]

        flags = Flags(
            enable_static_server=True,
            static_server_dir=static_server_dir)
        flags.plugins = load_plugins(
            b'proxy.http_proxy.HttpProxyPlugin,proxy.web_server.HttpWebServerPlugin')

        self.protocol_handler = ProtocolHandler(
            self.fileno, self._addr, flags=flags)
        self.protocol_handler.initialize()

        self.protocol_handler.run_once()
        self.protocol_handler.run_once()

        self.assertEqual(mock_selector.return_value.select.call_count, 2)
        self.assertEqual(self._conn.send.call_count, 1)
        self.assertEqual(self._conn.send.call_args[0][0], build_http_response(
            200, reason=b'OK', headers={
                b'Content-Type': b'text/html',
                b'Connection': b'close',
                b'Content-Length': bytes_(len(html_file_content)),
            },
            body=html_file_content
        ))

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_static_web_server_serves_404(
            self,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        self._conn.recv.return_value = build_http_request(b'GET', b'/not-found.html')

        mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)],
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_WRITE,
                data=None), selectors.EVENT_WRITE)], ]

        flags = Flags(enable_static_server=True)
        flags.plugins = load_plugins(
            b'proxy.http_proxy.HttpProxyPlugin,proxy.web_server.HttpWebServerPlugin')

        self.protocol_handler = ProtocolHandler(
            self.fileno, self._addr, flags=flags)
        self.protocol_handler.initialize()

        self.protocol_handler.run_once()
        self.protocol_handler.run_once()

        self.assertEqual(mock_selector.return_value.select.call_count, 2)
        self.assertEqual(self._conn.send.call_count, 1)
        self.assertEqual(self._conn.send.call_args[0][0],
                         HttpWebServerPlugin.DEFAULT_404_RESPONSE)

    @mock.patch('socket.fromfd')
    def test_on_client_connection_called_on_teardown(
            self, mock_fromfd: mock.Mock) -> None:
        flags = Flags()
        plugin = mock.MagicMock()
        flags.plugins = {b'ProtocolHandlerPlugin': [plugin]}
        self._conn = mock_fromfd.return_value
        self.protocol_handler = ProtocolHandler(
            self.fileno, self._addr, flags=flags)
        self.protocol_handler.initialize()
        plugin.assert_called()
        with mock.patch.object(self.protocol_handler, 'run_once') as mock_run_once:
            mock_run_once.return_value = True
            self.protocol_handler.run()
        self.assertTrue(self._conn.closed)
        plugin.return_value.on_client_connection_close.assert_called()

    def init_and_make_pac_file_request(self, pac_file: str) -> None:
        flags = Flags(pac_file=pac_file)
        flags.plugins = load_plugins(
            b'proxy.http_proxy.HttpProxyPlugin,proxy.web_server.HttpWebServerPlugin,'
            b'proxy.web_server.HttpWebServerPacFilePlugin')
        self.protocol_handler = ProtocolHandler(
            self.fileno, self._addr, flags=flags)
        self.protocol_handler.initialize()
        self._conn.recv.return_value = CRLF.join([
            b'GET / HTTP/1.1',
            CRLF,
        ])

    def mock_selector_for_client_read(self, mock_selector: mock.Mock) -> None:
        mock_selector.return_value.select.return_value = [(
            selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ), ]

