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
from unittest import mock

from proxy.common.utils import build_websocket_handshake_response, build_websocket_handshake_request
from proxy.http.websocket import WebsocketClient, WebsocketFrame
from proxy.common.constants import DEFAULT_PORT


class TestWebsocketClient(unittest.TestCase):

    @mock.patch('proxy.http.websocket.client.socket.gethostbyname')
    @mock.patch('base64.b64encode')
    @mock.patch('proxy.http.websocket.client.new_socket_connection')
    def test_handshake(
        self, mock_connect: mock.Mock,
        mock_b64encode: mock.Mock,
        mock_gethostbyname: mock.Mock,
    ) -> None:
        key = b'MySecretKey'
        mock_b64encode.return_value = key
        mock_gethostbyname.return_value = '127.0.0.1'
        mock_connect.return_value.recv.return_value = \
            build_websocket_handshake_response(
                WebsocketFrame.key_to_accept(key),
            )
        client = WebsocketClient(b'localhost', DEFAULT_PORT)
        mock_connect.return_value.send.assert_not_called()
        client.handshake()
        mock_connect.return_value.send.assert_called_with(
            build_websocket_handshake_request(key),
        )
