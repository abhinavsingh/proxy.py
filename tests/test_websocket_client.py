# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
from unittest import mock

from proxy.utils import build_websocket_handshake_response, build_websocket_handshake_request
from proxy.websocket import WebsocketClient, WebsocketFrame
from proxy.constants import DEFAULT_IPV4_HOSTNAME, DEFAULT_PORT


class TestWebsocketClient(unittest.TestCase):

    @mock.patch('base64.b64encode')
    @mock.patch('proxy.websocket.new_socket_connection')
    def test_handshake(self, mock_connect: mock.Mock, mock_b64encode: mock.Mock) -> None:
        key = b'MySecretKey'
        mock_b64encode.return_value = key
        mock_connect.return_value.recv.return_value = \
            build_websocket_handshake_response(WebsocketFrame.key_to_accept(key))
        _ = WebsocketClient(DEFAULT_IPV4_HOSTNAME, DEFAULT_PORT)
        mock_connect.return_value.send.assert_called_with(
            build_websocket_handshake_request(key)
        )
