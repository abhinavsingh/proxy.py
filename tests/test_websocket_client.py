

class TestWebsocketClient(unittest.TestCase):

    @mock.patch('base64.b64encode')
    @mock.patch('proxy.new_socket_connection')
    def test_handshake(self, mock_connect: mock.Mock, mock_b64encode: mock.Mock) -> None:
        key = b'MySecretKey'
        mock_b64encode.return_value = key
        mock_connect.return_value.recv.return_value = \
            proxy.build_websocket_handshake_response(proxy.WebsocketFrame.key_to_accept(key))
        _ = proxy.WebsocketClient(proxy.DEFAULT_IPV4_HOSTNAME, 8899)
        mock_connect.return_value.send.assert_called_with(
            proxy.build_websocket_handshake_request(key)
        )
