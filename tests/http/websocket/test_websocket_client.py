# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import selectors

import unittest
from unittest import mock

from proxy.common.utils import (
    build_websocket_handshake_request, build_websocket_handshake_response,
)
from proxy.http.websocket import WebsocketFrame, WebsocketClient
from proxy.common.constants import DEFAULT_PORT, DEFAULT_BUFFER_SIZE


class TestWebsocketClient(unittest.TestCase):

    @mock.patch('base64.b64encode')
    @mock.patch('proxy.http.websocket.client.socket.gethostbyname')
    @mock.patch('proxy.http.websocket.client.new_socket_connection')
    def test_handshake_success(
            self,
            mock_connect: mock.Mock,
            mock_gethostbyname: mock.Mock,
            mock_b64encode: mock.Mock,
    ) -> None:
        key = b'MySecretKey'
        mock_b64encode.return_value = key
        mock_gethostbyname.return_value = '127.0.0.1'
        mock_connect.return_value.recv.return_value = \
            build_websocket_handshake_response(
                WebsocketFrame.key_to_accept(key),
            )
        mock_connect.assert_not_called()
        client = WebsocketClient(b'localhost', DEFAULT_PORT)
        mock_connect.assert_called_once()
        mock_connect.return_value.send.assert_not_called()
        client.handshake()
        mock_connect.return_value.send.assert_called_with(
            build_websocket_handshake_request(key),
        )
        mock_connect.return_value.recv.assert_called_once_with(
            DEFAULT_BUFFER_SIZE,
        )

    @mock.patch('base64.b64encode')
    @mock.patch('selectors.DefaultSelector')
    @mock.patch('proxy.http.websocket.client.new_socket_connection')
    def test_send_recv_frames_success(
            self,
            mock_connect: mock.Mock,
            mock_selector: mock.Mock,
            mock_b64encode: mock.Mock,
    ):
        key = b'MySecretKey'
        mock_b64encode.return_value = key
        mock_connect.return_value.recv.side_effect = [
            build_websocket_handshake_response(
                WebsocketFrame.key_to_accept(key),
            ),
            WebsocketFrame.text(b'world'),
        ]

        def on_message(frame: WebsocketFrame):
            assert frame.build() == WebsocketFrame.text(b'world')

        client = WebsocketClient(
            b'localhost', DEFAULT_PORT, on_message=on_message,
        )
        mock_selector.assert_called_once()
        client.handshake()
        client.queue(memoryview(WebsocketFrame.text(b'hello')))
        mock_connect.return_value.send.assert_called_once()
        mock_selector.return_value.select.side_effect = [
            [
                (mock.Mock(), selectors.EVENT_WRITE),
            ],
        ]
        client.run_once()
        self.assertEqual(mock_connect.return_value.send.call_count, 2)
        mock_selector.return_value.select.side_effect = [
            [
                (mock.Mock(), selectors.EVENT_READ),
            ],
        ]
        client.run_once()

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('proxy.http.websocket.client.new_socket_connection')
    def test_run(
            self,
            mock_connect: mock.Mock,
            mock_selector: mock.Mock,
    ) -> None:
        mock_selector.return_value.select.side_effect = KeyboardInterrupt
        client = WebsocketClient(b'localhost', DEFAULT_PORT)
        client.run()
        mock_connect.return_value.shutdown.assert_called_once()
        mock_connect.return_value.close.assert_called_once()
        mock_selector.return_value.unregister.assert_called_once_with(mock_connect.return_value)
        mock_selector.return_value.close.assert_called_once()
