
class TestHttpProtocolHandler(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self,
              mock_fromfd: mock.Mock,
              mock_selector: mock.Mock) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = mock_fromfd.return_value

        self.http_server_port = 65535
        self.flags = proxy.Flags()
        self.flags.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.mock_selector = mock_selector
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, flags=self.flags)
        self.proxy.initialize()

    @mock.patch('proxy.TcpServerConnection')
    def test_http_get(self, mock_server_connection: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0
        self.mock_selector_for_client_read_read_server_write(self.mock_selector, server)

        # Send request line
        assert self.http_server_port is not None
        self._conn.recv.return_value = (b'GET http://localhost:%d HTTP/1.1' %
                                        self.http_server_port) + proxy.CRLF
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.LINE_RCVD)
        self.assertNotEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)

        # Send headers and blank line, thus completing HTTP request
        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            proxy.CRLF
        ])
        self.assert_data_queued(mock_server_connection, server)
        self.proxy.run_once()
        server.flush.assert_called_once()

    def assert_tunnel_response(
            self, mock_server_connection: mock.Mock, server: mock.Mock) -> None:
        self.proxy.run_once()
        self.assertTrue(
            cast(proxy.HttpProxyPlugin, self.proxy.plugins['HttpProxyPlugin']).server is not None)
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.queue.assert_not_called()
        server.closed = False

        parser = proxy.HttpParser(proxy.httpParserTypes.RESPONSE_PARSER)
        parser.parse(self.proxy.client.buffer)
        self.assertEqual(parser.state, proxy.httpParserStates.COMPLETE)
        assert parser.code is not None
        self.assertEqual(int(parser.code), 200)

    @mock.patch('proxy.TcpServerConnection')
    def test_http_tunnel(self, mock_server_connection: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True

        def has_buffer() -> bool:
            return cast(bool, server.queue.called)

        server.has_buffer.side_effect = has_buffer
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ), ],
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=0,
                data=None), selectors.EVENT_WRITE), ],
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ), ],
            [(selectors.SelectorKey(
                fileobj=server.connection,
                fd=server.connection.fileno,
                events=0,
                data=None), selectors.EVENT_WRITE), ],
        ]

        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Proxy-Connection: Keep-Alive',
            proxy.CRLF
        ])
        self.assert_tunnel_response(mock_server_connection, server)

        # Dispatch tunnel established response to client
        self.proxy.run_once()
        self.assert_data_queued_to_server(server)

        self.proxy.run_once()
        self.assertEqual(server.queue.call_count, 1)
        server.flush.assert_called_once()

    def test_proxy_connection_failed(self) -> None:
        self.mock_selector_for_client_read(self.mock_selector)
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET http://unknown.domain HTTP/1.1',
            b'Host: unknown.domain',
            proxy.CRLF
        ])
        self.proxy.run_once()
        self.assertEqual(self.proxy.client.buffer, proxy.ProxyConnectionFailed.RESPONSE_PKT)

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_proxy_authentication_failed(
            self,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)
        flags = proxy.Flags(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        flags.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, flags=flags)
        self.proxy.initialize()
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET http://abhinavsingh.com HTTP/1.1',
            b'Host: abhinavsingh.com',
            proxy.CRLF
        ])
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.ProxyAuthenticationFailed.RESPONSE_PKT)

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_get(
            self, mock_server_connection: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)

        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0

        flags = proxy.Flags(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        flags.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, addr=self._addr, flags=flags)
        self.proxy.initialize()
        assert self.http_server_port is not None

        self._conn.recv.return_value = b'GET http://localhost:%d HTTP/1.1' % self.http_server_port
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.INITIALIZED)

        self._conn.recv.return_value = proxy.CRLF
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.LINE_RCVD)

        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ])
        self.assert_data_queued(mock_server_connection, server)

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_tunnel(
            self, mock_server_connection: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.buffer_size.return_value = 0
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read_read_server_write(mock_selector, server)

        flags = proxy.Flags(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        flags.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, flags=flags)
        self.proxy.initialize()

        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ])
        self.assert_tunnel_response(mock_server_connection, server)
        self.proxy.client.flush()
        self.assert_data_queued_to_server(server)

        self.proxy.run_once()
        server.flush.assert_called_once()

    def mock_selector_for_client_read_read_server_write(self, mock_selector: mock.Mock, server: mock.Mock) -> None:
        mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ), ],
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=0,
                data=None), selectors.EVENT_READ), ],
            [(selectors.SelectorKey(
                fileobj=server.connection,
                fd=server.connection.fileno,
                events=0,
                data=None), selectors.EVENT_WRITE), ],
        ]

    def assert_data_queued(
            self, mock_server_connection: mock.Mock, server: mock.Mock) -> None:
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.closed = False
        assert self.http_server_port is not None
        pkt = proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Via: %s' % b'1.1 proxy.py v%s' % proxy.version,
            proxy.CRLF
        ])
        server.queue.assert_called_once_with(pkt)
        server.buffer_size.return_value = len(pkt)

    def assert_data_queued_to_server(self, server: mock.Mock) -> None:
        assert self.http_server_port is not None
        self.assertEqual(
            self._conn.send.call_args[0][0],
            proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)

        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ])
        self.proxy.run_once()

        pkt = proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ])
        server.queue.assert_called_once_with(pkt)
        server.buffer_size.return_value = len(pkt)
        server.flush.assert_not_called()

    def mock_selector_for_client_read(self, mock_selector: mock.Mock) -> None:
        mock_selector.return_value.select.return_value = [(
            selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ), ]
