# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import base64
import errno
import ipaddress
import json
import logging
import multiprocessing
import os
import selectors
import socket
import ssl
import tempfile
import unittest
import uuid
from contextlib import closing
from typing import Dict, Optional, Tuple, Union, Any, cast, Type
from unittest import mock
from urllib import parse as urlparse

import plugin_examples
import proxy

if os.name != 'nt':
    import resource

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')


def get_temp_file(name: str) -> str:
    return os.path.join(tempfile.gettempdir(), name)


def get_available_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
        return int(port)


def get_plugin_by_test_name(test_name: str) -> Type[proxy.HttpProxyBasePlugin]:
    plugin: Type[proxy.HttpProxyBasePlugin] = plugin_examples.ModifyPostDataPlugin
    if test_name == 'test_modify_post_data_plugin':
        plugin = plugin_examples.ModifyPostDataPlugin
    elif test_name == 'test_proposed_rest_api_plugin':
        plugin = plugin_examples.ProposedRestApiPlugin
    elif test_name == 'test_redirect_to_custom_server_plugin':
        plugin = plugin_examples.RedirectToCustomServerPlugin
    elif test_name == 'test_filter_by_upstream_host_plugin':
        plugin = plugin_examples.FilterByUpstreamHostPlugin
    elif test_name == 'test_cache_responses_plugin':
        plugin = plugin_examples.CacheResponsesPlugin
    elif test_name == 'test_man_in_the_middle_plugin':
        plugin = plugin_examples.ManInTheMiddlePlugin
    return plugin


class TestTextBytes(unittest.TestCase):

    def test_text(self) -> None:
        self.assertEqual(proxy.text_(b'hello'), 'hello')

    def test_text_int(self) -> None:
        self.assertEqual(proxy.text_(1), '1')

    def test_text_nochange(self) -> None:
        self.assertEqual(proxy.text_('hello'), 'hello')

    def test_bytes(self) -> None:
        self.assertEqual(proxy.bytes_('hello'), b'hello')

    def test_bytes_int(self) -> None:
        self.assertEqual(proxy.bytes_(1), b'1')

    def test_bytes_nochange(self) -> None:
        self.assertEqual(proxy.bytes_(b'hello'), b'hello')


class TestTcpConnection(unittest.TestCase):
    class TcpConnectionToTest(proxy.TcpConnection):

        def __init__(self, conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None,
                     tag: int = proxy.tcpConnectionTypes.CLIENT) -> None:
            super().__init__(tag)
            self._conn = conn

        @property
        def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
            if self._conn is None:
                raise proxy.TcpConnectionUninitializedException()
            return self._conn

    def testFlushThrowsBrokenPipeIfClosed(self) -> None:
        self.conn = TestTcpConnection.TcpConnectionToTest()
        self.conn.queue(b'some data')
        self.conn.closed = True
        with self.assertRaises(BrokenPipeError):
            self.conn.flush()

    def testThrowsKeyErrorIfNoConn(self) -> None:
        self.conn = TestTcpConnection.TcpConnectionToTest()
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            self.conn.send(b'dummy')
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            self.conn.recv()
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            self.conn.close()

    def testHandlesIOError(self) -> None:
        _conn = mock.MagicMock()
        _conn.recv.side_effect = IOError()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        with mock.patch('proxy.logger') as mock_logger:
            self.conn.recv()
            mock_logger.exception.assert_called()
            logging.info(mock_logger.exception.call_args[0][0].startswith(
                'Exception while receiving from connection'))

    def testHandlesConnReset(self) -> None:
        _conn = mock.MagicMock()
        e = IOError()
        e.errno = errno.ECONNRESET
        _conn.recv.side_effect = e
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        with mock.patch('proxy.logger') as mock_logger:
            self.conn.recv()
            mock_logger.exception.assert_not_called()
            mock_logger.debug.assert_called()
            self.assertEqual(mock_logger.debug.call_args[0][0], '%r' % e)

    def testClosesIfNotClosed(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.close()
        _conn.close.assert_called()
        self.assertTrue(self.conn.closed)

    def testNoOpIfAlreadyClosed(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.closed = True
        self.conn.close()
        _conn.close.assert_not_called()
        self.assertTrue(self.conn.closed)

    def testFlushReturnsIfNoBuffer(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.flush()
        self.assertTrue(not _conn.send.called)

    @mock.patch('socket.socket')
    def testTcpServerEstablishesIPv6Connection(
            self, mock_socket: mock.Mock) -> None:
        conn = proxy.TcpServerConnection(
            str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT)
        conn.connect()
        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(
            (str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT, 0, 0))

    @mock.patch('proxy.new_socket_connection')
    def testTcpServerIgnoresDoubleConnectSilently(
            self,
            mock_new_socket_connection: mock.Mock) -> None:
        conn = proxy.TcpServerConnection(
            str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT)
        conn.connect()
        conn.connect()
        mock_new_socket_connection.assert_called_once()

    @mock.patch('socket.socket')
    def testTcpServerEstablishesIPv4Connection(
            self, mock_socket: mock.Mock) -> None:
        conn = proxy.TcpServerConnection(
            str(proxy.DEFAULT_IPV4_HOSTNAME), proxy.DEFAULT_PORT)
        conn.connect()
        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(
            (str(proxy.DEFAULT_IPV4_HOSTNAME), proxy.DEFAULT_PORT))

    @mock.patch('proxy.new_socket_connection')
    def testTcpServerConnectionProperty(
            self,
            mock_new_socket_connection: mock.Mock) -> None:
        conn = proxy.TcpServerConnection(
            str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT)
        conn.connect()
        self.assertEqual(conn.connection, mock_new_socket_connection.return_value)

    def testTcpServerRaisesTcpConnectionUninitializedException(self) -> None:
        conn = proxy.TcpServerConnection(
            str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT)
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            _ = conn.connection

    def testTcpClientRaisesTcpConnectionUninitializedException(self) -> None:
        _conn = mock.MagicMock()
        _addr = mock.MagicMock()
        conn = proxy.TcpClientConnection(_conn, _addr)
        conn._conn = None
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            _ = conn.connection


class TestSocketConnectionUtils(unittest.TestCase):

    def setUp(self) -> None:
        self.addr_ipv4 = (str(proxy.DEFAULT_IPV4_HOSTNAME), proxy.DEFAULT_PORT)
        self.addr_ipv6 = (str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT)
        self.addr_dual = ('httpbin.org', 80)

    @mock.patch('socket.socket')
    def test_new_socket_connection_ipv4(self, mock_socket: mock.Mock) -> None:
        conn = proxy.new_socket_connection(self.addr_ipv4)
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.assertEqual(conn, mock_socket.return_value)
        mock_socket.return_value.connect.assert_called_with(self.addr_ipv4)

    @mock.patch('socket.socket')
    def test_new_socket_connection_ipv6(self, mock_socket: mock.Mock) -> None:
        conn = proxy.new_socket_connection(self.addr_ipv6)
        mock_socket.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM, 0)
        self.assertEqual(conn, mock_socket.return_value)
        mock_socket.return_value.connect.assert_called_with(
            (self.addr_ipv6[0], self.addr_ipv6[1], 0, 0))

    @mock.patch('socket.create_connection')
    def test_new_socket_connection_dual(self, mock_socket: mock.Mock) -> None:
        conn = proxy.new_socket_connection(self.addr_dual)
        mock_socket.assert_called_with(self.addr_dual)
        self.assertEqual(conn, mock_socket.return_value)

    @mock.patch('proxy.new_socket_connection')
    def test_decorator(self, mock_new_socket_connection: mock.Mock) -> None:
        @proxy.socket_connection(self.addr_ipv4)
        def dummy(conn: socket.socket) -> None:
            self.assertEqual(conn, mock_new_socket_connection.return_value)
        dummy()     # type: ignore

    @mock.patch('proxy.new_socket_connection')
    def test_context_manager(self, mock_new_socket_connection: mock.Mock) -> None:
        with proxy.socket_connection(self.addr_ipv4) as conn:
            self.assertEqual(conn, mock_new_socket_connection.return_value)


class TestAcceptorPool(unittest.TestCase):

    @mock.patch('proxy.send_handle')
    @mock.patch('multiprocessing.Pipe')
    @mock.patch('socket.socket')
    @mock.patch('proxy.Worker')
    def test_setup_and_shutdown(
            self,
            mock_worker: mock.Mock,
            mock_socket: mock.Mock,
            mock_pipe: mock.Mock,
            _mock_send_handle: mock.Mock) -> None:
        mock_worker1 = mock.MagicMock()
        mock_worker2 = mock.MagicMock()
        mock_worker.side_effect = [mock_worker1, mock_worker2]

        num_workers = 2
        sock = mock_socket.return_value
        work_klass = mock.MagicMock()
        kwargs = {'config': proxy.ProtocolConfig()}
        acceptor = proxy.AcceptorPool(
            ipaddress.ip_address(proxy.DEFAULT_IPV6_HOSTNAME),
            proxy.DEFAULT_PORT,
            proxy.DEFAULT_BACKLOG,
            num_workers,
            work_klass=work_klass,
            **kwargs
        )

        acceptor.setup()

        mock_socket.assert_called_with(
            socket.AF_INET6 if acceptor.hostname.version == 6 else socket.AF_INET,
            socket.SOCK_STREAM
        )
        sock.setsockopt.assert_called_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind.assert_called_with((str(acceptor.hostname), acceptor.port))
        sock.listen.assert_called_with(acceptor.backlog)
        sock.setblocking.assert_called_with(False)
        sock.settimeout.assert_called_with(0)

        self.assertTrue(mock_pipe.call_count, num_workers)
        self.assertTrue(mock_worker.call_count, num_workers)
        mock_worker1.start.assert_called()
        mock_worker1.join.assert_not_called()
        mock_worker2.start.assert_called()
        mock_worker2.join.assert_not_called()

        sock.close.assert_called()

        acceptor.shutdown()
        mock_worker1.join.assert_called()
        mock_worker2.join.assert_called()


class TestWorker(unittest.TestCase):

    @mock.patch('proxy.ProtocolHandler')
    def setUp(self, mock_protocol_handler: mock.Mock) -> None:
        self.pipe = multiprocessing.Pipe()
        self.protocol_config = proxy.ProtocolConfig()
        self.worker = proxy.Worker(
            self.pipe[1],
            mock_protocol_handler,
            config=self.protocol_config)
        self.mock_protocol_handler = mock_protocol_handler

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.recv_handle')
    def test_continues_when_no_events(
            self,
            mock_recv_handle: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
        fileno = 10
        conn = mock.MagicMock()
        addr = mock.MagicMock()
        sock = mock_fromfd.return_value
        mock_fromfd.return_value.accept.return_value = (conn, addr)
        mock_recv_handle.return_value = fileno

        selector = mock_selector.return_value
        selector.select.side_effect = [[], KeyboardInterrupt()]

        self.pipe[0].send(socket.AF_INET6)
        self.worker.run()

        sock.accept.assert_not_called()
        self.mock_protocol_handler.assert_not_called()

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.recv_handle')
    def test_worker_doesnt_teardown_on_blocking_io_error(
            self,
            mock_recv_handle: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
        fileno = 10
        conn = mock.MagicMock()
        addr = mock.MagicMock()
        sock = mock_fromfd.return_value
        mock_fromfd.return_value.accept.return_value = (conn, addr)
        mock_recv_handle.return_value = fileno

        selector = mock_selector.return_value
        selector.select.side_effect = [(None, None), KeyboardInterrupt()]
        sock.accept.side_effect = BlockingIOError()

        self.pipe[0].send(socket.AF_INET6)
        self.worker.run()

        self.mock_protocol_handler.assert_not_called()

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.recv_handle')
    def test_accepts_client_from_server_socket(
            self,
            mock_recv_handle: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
        fileno = 10
        conn = mock.MagicMock()
        addr = mock.MagicMock()
        sock = mock_fromfd.return_value
        mock_fromfd.return_value.accept.return_value = (conn, addr)
        mock_recv_handle.return_value = fileno

        self.mock_protocol_handler.return_value.start.side_effect = KeyboardInterrupt()

        selector = mock_selector.return_value
        selector.select.return_value = [(None, None)]

        self.pipe[0].send(socket.AF_INET6)
        self.worker.run()

        selector.register.assert_called_with(sock, selectors.EVENT_READ)
        selector.unregister.assert_called_with(sock)
        mock_recv_handle.assert_called_with(self.pipe[1])
        mock_fromfd.assert_called_with(
            fileno,
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM
        )
        self.mock_protocol_handler.assert_called_with(
            fileno=conn.fileno(),
            addr=addr,
            **{'config': self.protocol_config}
        )
        self.mock_protocol_handler.return_value.setDaemon.assert_called()
        self.mock_protocol_handler.return_value.start.assert_called()
        sock.close.assert_called()


class TestChunkParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = proxy.ChunkParser()

    def test_chunk_parse_basic(self) -> None:
        self.parser.parse(b''.join([
            b'4\r\n',
            b'Wiki\r\n',
            b'5\r\n',
            b'pedia\r\n',
            b'E\r\n',
            b' in\r\n\r\nchunks.\r\n',
            b'0\r\n',
            b'\r\n'
        ]))
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, proxy.chunkParserStates.COMPLETE)

    def test_chunk_parse_issue_27(self) -> None:
        """Case when data ends with the chunk size but without ending CRLF."""
        self.parser.parse(b'3')
        self.assertEqual(self.parser.chunk, b'3')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 3)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_DATA)
        self.parser.parse(b'abc')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'4\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 4)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_DATA)
        self.parser.parse(b'defg\r\n0')
        self.assertEqual(self.parser.chunk, b'0')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(self.parser.state, proxy.chunkParserStates.COMPLETE)

    def test_to_chunks(self) -> None:
        self.assertEqual(b'f\r\n{"key":"value"}\r\n0\r\n\r\n', proxy.ChunkParser.to_chunks(b'{"key":"value"}'))


class TestHttpParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = proxy.HttpParser(proxy.httpParserTypes.REQUEST_PARSER)

    def test_build_request(self) -> None:
        self.assertEqual(
            proxy.build_http_request(
                b'GET', b'http://localhost:12345', b'HTTP/1.1'),
            proxy.CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                proxy.CRLF
            ]))
        self.assertEqual(
            proxy.build_http_request(b'GET', b'http://localhost:12345', b'HTTP/1.1',
                                     headers={b'key': b'value'}),
            proxy.CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                proxy.CRLF
            ]))
        self.assertEqual(
            proxy.build_http_request(b'GET', b'http://localhost:12345', b'HTTP/1.1',
                                     headers={b'key': b'value'},
                                     body=b'Hello from proxy.py'),
            proxy.CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                proxy.CRLF
            ]) + b'Hello from proxy.py')

    def test_build_response(self) -> None:
        self.assertEqual(
            proxy.build_http_response(
                200, reason=b'OK', protocol_version=b'HTTP/1.1'),
            proxy.CRLF.join([
                b'HTTP/1.1 200 OK',
                proxy.CRLF
            ]))
        self.assertEqual(
            proxy.build_http_response(200, reason=b'OK', protocol_version=b'HTTP/1.1',
                                      headers={b'key': b'value'}),
            proxy.CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                proxy.CRLF
            ]))

    def test_build_response_adds_content_length_header(self) -> None:
        body = b'Hello world!!!'
        self.assertEqual(
            proxy.build_http_response(200, reason=b'OK', protocol_version=b'HTTP/1.1',
                                      headers={b'key': b'value'},
                                      body=body),
            proxy.CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                b'Content-Length: ' + proxy.bytes_(len(body)),
                proxy.CRLF
            ]) + body)

    def test_build_header(self) -> None:
        self.assertEqual(
            proxy.build_http_header(
                b'key', b'value'), b'key: value')

    def test_header_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.parser.header(b'not-found')

    def test_has_header(self) -> None:
        self.parser.add_header(b'key', b'value')
        self.assertFalse(self.parser.has_header(b'not-found'))
        self.assertTrue(self.parser.has_header(b'key'))

    def test_set_host_port_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.parser.set_line_attributes()

    def test_find_line(self) -> None:
        self.assertEqual(
            proxy.find_http_line(
                b'CONNECT python.org:443 HTTP/1.0\r\n\r\n'),
            (b'CONNECT python.org:443 HTTP/1.0',
             proxy.CRLF))

    def test_find_line_returns_None(self) -> None:
        self.assertEqual(
            proxy.find_http_line(b'CONNECT python.org:443 HTTP/1.0'),
            (None,
             b'CONNECT python.org:443 HTTP/1.0'))

    def test_connect_request_with_crlf_as_separate_chunk(self) -> None:
        """See https://github.com/abhinavsingh/proxy.py/issues/70 for background."""
        raw = b'CONNECT pypi.org:443 HTTP/1.0\r\n'
        self.parser.parse(raw)
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_get_full_parse(self) -> None:
        raw = proxy.CRLF.join([
            b'GET %s HTTP/1.1',
            b'Host: %s',
            proxy.CRLF
        ])
        pkt = raw % (b'https://example.com/path/dir/?a=b&c=d#p=q',
                     b'example.com')
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assertEqual(self.parser.build_url(), b'/path/dir/?a=b&c=d#p=q')
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'example.com')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'example.com')}, self.parser.headers)
        self.parser.del_headers([b'host'])
        self.parser.add_headers([(b'Host', b'example.com')])
        self.assertEqual(
            raw %
            (b'/path/dir/?a=b&c=d#p=q',
             b'example.com'),
            self.parser.build())

    def test_build_url_none(self) -> None:
        self.assertEqual(self.parser.build_url(), b'/None')

    def test_line_rcvd_to_rcving_headers_state_change(self) -> None:
        pkt = b'GET http://localhost HTTP/1.1'
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assert_state_change_with_crlf(
            proxy.httpParserStates.INITIALIZED,
            proxy.httpParserStates.LINE_RCVD,
            proxy.httpParserStates.COMPLETE)

    def test_get_partial_parse1(self) -> None:
        pkt = proxy.CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1'
        ])
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assertEqual(self.parser.method, None)
        self.assertEqual(self.parser.url, None)
        self.assertEqual(self.parser.version, None)
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.INITIALIZED)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.total_size, len(pkt) + len(proxy.CRLF))
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)

        host_hdr = b'Host: localhost:8080'
        self.parser.parse(host_hdr)
        self.assertEqual(self.parser.total_size,
                         len(pkt) + len(proxy.CRLF) + len(host_hdr))
        self.assertDictEqual(self.parser.headers, dict())
        self.assertEqual(self.parser.buffer, b'Host: localhost:8080')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)

        self.parser.parse(proxy.CRLF * 2)
        self.assertEqual(self.parser.total_size, len(pkt) +
                         (3 * len(proxy.CRLF)) + len(host_hdr))
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_get_partial_parse2(self) -> None:
        self.parser.parse(proxy.CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1',
            b'Host: '
        ]))
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.buffer, b'Host: ')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)

        self.parser.parse(b'localhost:8080' + proxy.CRLF)
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_HEADERS)

        self.parser.parse(b'Content-Type: text/plain' + proxy.CRLF)
        self.assertEqual(self.parser.buffer, b'')
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'text/plain')}, self.parser.headers)
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_HEADERS)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_post_full_parse(self) -> None:
        raw = proxy.CRLF.join([
            b'POST %s HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded' + proxy.CRLF,
            b'a=b&c=d'
        ])
        self.parser.parse(raw % b'http://localhost')
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'application/x-www-form-urlencoded')}, self.parser.headers)
        self.assertDictContainsSubset(
            {b'content-length': (b'Content-Length', b'7')}, self.parser.headers)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % b'/'))

    def assert_state_change_with_crlf(self,
                                      initial_state: int,
                                      next_state: int,
                                      final_state: int) -> None:
        self.assertEqual(self.parser.state, initial_state)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, next_state)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, final_state)

    def test_post_partial_parse(self) -> None:
        self.parser.parse(proxy.CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded'
        ]))
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assert_state_change_with_crlf(
            proxy.httpParserStates.RCVING_HEADERS,
            proxy.httpParserStates.RCVING_HEADERS,
            proxy.httpParserStates.HEADERS_COMPLETE)

        self.parser.parse(b'a=b')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_BODY)
        self.assertEqual(self.parser.body, b'a=b')
        self.assertEqual(self.parser.buffer, b'')

        self.parser.parse(b'&c=d')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')

    def test_connect_request_without_host_header_request_parse(self) -> None:
        """Case where clients can send CONNECT request without a Host header field.

        Example:
            1. pip3 --proxy http://localhost:8899 install <package name>
               Uses HTTP/1.0, Host header missing with CONNECT requests
            2. Android Emulator
               Uses HTTP/1.1, Host header missing with CONNECT requests

        See https://github.com/abhinavsingh/proxy.py/issues/5 for details.
        """
        self.parser.parse(b'CONNECT pypi.org:443 HTTP/1.0\r\n\r\n')
        self.assertEqual(self.parser.method, b'CONNECT')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_request_parse_without_content_length(self) -> None:
        """Case when incoming request doesn't contain a content-length header.

        From http://w3-org.9356.n7.nabble.com/POST-with-empty-body-td103965.html
        'A POST with no content-length and no body is equivalent to a POST with Content-Length: 0
        and nothing following, as could perfectly happen when you upload an empty file for instance.'

        See https://github.com/abhinavsingh/proxy.py/issues/20 for details.
        """
        self.parser.parse(proxy.CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Type: application/x-www-form-urlencoded',
            proxy.CRLF
        ]))
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_response_parse_without_content_length(self) -> None:
        """Case when server response doesn't contain a content-length header for non-chunk response types.

        HttpParser by itself has no way to know if more data should be expected.
        In example below, parser reaches state httpParserStates.HEADERS_COMPLETE
        and it is responsibility of callee to change state to httpParserStates.COMPLETE
        when server stream closes.

        See https://github.com/abhinavsingh/proxy.py/issues/20 for details.
        """
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b'HTTP/1.0 200 OK' + proxy.CRLF)
        self.assertEqual(self.parser.code, b'200')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)
        self.parser.parse(proxy.CRLF.join([
            b'Server: BaseHTTP/0.3 Python/2.7.10',
            b'Date: Thu, 13 Dec 2018 16:24:09 GMT',
            proxy.CRLF
        ]))
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.HEADERS_COMPLETE)

    def test_response_parse(self) -> None:
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b''.join([
            b'HTTP/1.1 301 Moved Permanently\r\n',
            b'Location: http://www.google.com/\r\n',
            b'Content-Type: text/html; charset=UTF-8\r\n',
            b'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
            b'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
            b'Cache-Control: public, max-age=2592000\r\n',
            b'Server: gws\r\n',
            b'Content-Length: 219\r\n',
            b'X-XSS-Protection: 1; mode=block\r\n',
            b'X-Frame-Options: SAMEORIGIN\r\n\r\n',
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>',
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n'
        ]))
        self.assertEqual(self.parser.code, b'301')
        self.assertEqual(self.parser.reason, b'Moved Permanently')
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(
            self.parser.body,
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertDictContainsSubset(
            {b'content-length': (b'Content-Length', b'219')}, self.parser.headers)
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_response_partial_parse(self) -> None:
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b''.join([
            b'HTTP/1.1 301 Moved Permanently\r\n',
            b'Location: http://www.google.com/\r\n',
            b'Content-Type: text/html; charset=UTF-8\r\n',
            b'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
            b'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
            b'Cache-Control: public, max-age=2592000\r\n',
            b'Server: gws\r\n',
            b'Content-Length: 219\r\n',
            b'X-XSS-Protection: 1; mode=block\r\n',
            b'X-Frame-Options: SAMEORIGIN\r\n'
        ]))
        self.assertDictContainsSubset(
            {b'x-frame-options': (b'X-Frame-Options', b'SAMEORIGIN')}, self.parser.headers)
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_HEADERS)
        self.parser.parse(b'\r\n')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.HEADERS_COMPLETE)
        self.parser.parse(
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_BODY)
        self.parser.parse(
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_chunked_response_parse(self) -> None:
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b''.join([
            b'HTTP/1.1 200 OK\r\n',
            b'Content-Type: application/json\r\n',
            b'Date: Wed, 22 May 2013 15:08:15 GMT\r\n',
            b'Server: gunicorn/0.16.1\r\n',
            b'transfer-encoding: chunked\r\n',
            b'Connection: keep-alive\r\n\r\n',
            b'4\r\n',
            b'Wiki\r\n',
            b'5\r\n',
            b'pedia\r\n',
            b'E\r\n',
            b' in\r\n\r\nchunks.\r\n',
            b'0\r\n',
            b'\r\n'
        ]))
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_chunked_request_parse(self) -> None:
        self.parser.parse(proxy.build_http_request(
            proxy.httpMethods.POST, b'http://example.org/',
            headers={
                b'Transfer-Encoding': b'chunked',
                b'Content-Type': b'application/json',
            },
            body=b'f\r\n{"key":"value"}\r\n0\r\n\r\n'))
        self.assertEqual(self.parser.body, b'{"key":"value"}')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)
        self.assertEqual(self.parser.build(), proxy.build_http_request(
            proxy.httpMethods.POST, b'/',
            headers={
                b'Transfer-Encoding': b'chunked',
                b'Content-Type': b'application/json',
            },
            body=b'f\r\n{"key":"value"}\r\n0\r\n\r\n'))

    def test_is_http_1_1_keep_alive(self) -> None:
        self.parser.parse(proxy.build_http_request(
            proxy.httpMethods.GET, b'/'
        ))
        self.assertTrue(self.parser.is_http_1_1_keep_alive())

    def test_is_http_1_1_keep_alive_with_non_close_connection_header(self) -> None:
        self.parser.parse(proxy.build_http_request(
            proxy.httpMethods.GET, b'/',
            headers={
                b'Connection': b'keep-alive',
            }
        ))
        self.assertTrue(self.parser.is_http_1_1_keep_alive())

    def test_is_not_http_1_1_keep_alive_with_close_header(self) -> None:
        self.parser.parse(proxy.build_http_request(
            proxy.httpMethods.GET, b'/',
            headers={
                b'Connection': b'close',
            }
        ))
        self.assertFalse(self.parser.is_http_1_1_keep_alive())

    def test_is_not_http_1_1_keep_alive_for_http_1_0(self) -> None:
        self.parser.parse(proxy.build_http_request(
            proxy.httpMethods.GET, b'/', protocol_version=b'HTTP/1.0',
        ))
        self.assertFalse(self.parser.is_http_1_1_keep_alive())

    def assertDictContainsSubset(self, subset: Dict[bytes, Tuple[bytes, bytes]],
                                 dictionary: Dict[bytes, Tuple[bytes, bytes]]) -> None:
        for k in subset.keys():
            self.assertTrue(k in dictionary)


class TestWebsocketFrame(unittest.TestCase):

    def test_build_with_mask(self) -> None:
        raw = b'\x81\x85\xc6\ti\x8d\xael\x05\xe1\xa9'
        frame = proxy.WebsocketFrame()
        frame.fin = True
        frame.opcode = proxy.websocketOpcodes.TEXT_FRAME
        frame.masked = True
        frame.mask = b'\xc6\ti\x8d'
        frame.data = b'hello'
        self.assertEqual(frame.build(), raw)

    def test_parse_with_mask(self) -> None:
        raw = b'\x81\x85\xc6\ti\x8d\xael\x05\xe1\xa9'
        frame = proxy.WebsocketFrame()
        frame.parse(raw)
        self.assertEqual(frame.fin, True)
        self.assertEqual(frame.rsv1, False)
        self.assertEqual(frame.rsv2, False)
        self.assertEqual(frame.rsv3, False)
        self.assertEqual(frame.opcode, 0x1)
        self.assertEqual(frame.masked, True)
        assert frame.mask is not None
        self.assertEqual(frame.mask, b'\xc6\ti\x8d')
        self.assertEqual(frame.payload_length, 5)
        self.assertEqual(frame.data, b'hello')


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


class TestHttpProtocolHandler(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = mock_fromfd.return_value

        self.http_server_port = 65535
        self.config = proxy.ProtocolConfig()
        self.config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.mock_selector = mock_selector
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=self.config)
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
            self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)
        config = proxy.ProtocolConfig(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
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

        config = proxy.ProtocolConfig(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, addr=self._addr, config=config)
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

        config = proxy.ProtocolConfig(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
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


class TestWebServerPlugin(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = mock_fromfd.return_value
        self.mock_selector = mock_selector
        self.config = proxy.ProtocolConfig()
        self.config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=self.config)
        self.proxy.initialize()

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_pac_file_served_from_disk(
            self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        pac_file = 'proxy.pac'
        self._conn = mock_fromfd.return_value
        self.mock_selector_for_client_read(mock_selector)
        self.init_and_make_pac_file_request(pac_file)
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        with open('proxy.pac', 'rb') as f:
            self._conn.send.called_once_with(proxy.build_http_response(
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
        self.init_and_make_pac_file_request(proxy.text_(pac_file_content))
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        self._conn.send.called_once_with(proxy.build_http_response(
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
        config = proxy.ProtocolConfig()
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self.proxy.initialize()
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET /hello HTTP/1.1',
            proxy.CRLF,
        ])
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.HttpWebServerPlugin.DEFAULT_404_RESPONSE)

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
        self._conn.recv.return_value = proxy.build_http_request(b'GET', b'/index.html')

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

        config = proxy.ProtocolConfig(
            enable_static_server=True,
            static_server_dir=static_server_dir)
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self.proxy.initialize()

        self.proxy.run_once()
        self.proxy.run_once()

        self.assertEqual(mock_selector.return_value.select.call_count, 2)
        self.assertEqual(self._conn.send.call_count, 1)
        self.assertEqual(self._conn.send.call_args[0][0], proxy.build_http_response(
            200, reason=b'OK', headers={
                b'Content-Type': b'text/html',
                b'Content-Length': proxy.bytes_(len(html_file_content))
            },
            body=html_file_content
        ))

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_static_web_server_serves_404(
            self, mock_fromfd: mock.Mock, mock_selector: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        self._conn.recv.return_value = proxy.build_http_request(b'GET', b'/not-found.html')

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

        config = proxy.ProtocolConfig(enable_static_server=True)
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self.proxy.initialize()

        self.proxy.run_once()
        self.proxy.run_once()

        self.assertEqual(mock_selector.return_value.select.call_count, 2)
        self.assertEqual(self._conn.send.call_count, 1)
        self.assertEqual(self._conn.send.call_args[0][0],
                         proxy.HttpWebServerPlugin.DEFAULT_404_RESPONSE)

    @mock.patch('socket.fromfd')
    def test_on_client_connection_called_on_teardown(
            self, mock_fromfd: mock.Mock) -> None:
        config = proxy.ProtocolConfig()
        plugin = mock.MagicMock()
        config.plugins = {b'ProtocolHandlerPlugin': [plugin]}
        self._conn = mock_fromfd.return_value
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self.proxy.initialize()
        plugin.assert_called()
        with mock.patch.object(self.proxy, 'run_once') as mock_run_once:
            mock_run_once.return_value = True
            self.proxy.run()
        self.assertTrue(self._conn.closed)
        plugin.return_value.on_client_connection_close.assert_called()

    def init_and_make_pac_file_request(self, pac_file: str) -> None:
        config = proxy.ProtocolConfig(pac_file=pac_file)
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin,proxy.HttpWebServerPacFilePlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self.proxy.initialize()
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET / HTTP/1.1',
            proxy.CRLF,
        ])

    def mock_selector_for_client_read(self, mock_selector: mock.Mock) -> None:
        mock_selector.return_value.select.return_value = [(
            selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ), ]


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
        self.config = proxy.ProtocolConfig()
        self.plugin = mock.MagicMock()
        self.config.plugins = {
            b'ProtocolHandlerPlugin': [proxy.HttpProxyPlugin],
            b'HttpProxyBasePlugin': [self.plugin]
        }
        self._conn = mock_fromfd.return_value
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=self.config)
        self.proxy.initialize()

    def test_proxy_plugin_initialized(self) -> None:
        self.plugin.assert_called()

    @mock.patch('proxy.TcpServerConnection')
    def test_proxy_plugin_on_and_before_upstream_connection(
            self,
            mock_server_conn: mock.Mock) -> None:
        self.plugin.return_value.before_upstream_connection.side_effect = lambda r: r
        self.plugin.return_value.handle_client_request.side_effect = lambda r: r

        self._conn.recv.return_value = proxy.build_http_request(
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

        self.proxy.run_once()
        mock_server_conn.assert_called_with('upstream.host', 80)
        self.plugin.return_value.before_upstream_connection.assert_called()
        self.plugin.return_value.handle_client_request.assert_called()

    @mock.patch('proxy.TcpServerConnection')
    def test_proxy_plugin_before_upstream_connection_can_teardown(
            self,
            mock_server_conn: mock.Mock) -> None:
        self.plugin.return_value.before_upstream_connection.side_effect = proxy.ProtocolException()

        self._conn.recv.return_value = proxy.build_http_request(
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

        self.proxy.run_once()
        self.plugin.return_value.before_upstream_connection.assert_called()
        mock_server_conn.assert_not_called()


class TestHttpProxyPluginExamples(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self,
              mock_fromfd: mock.Mock,
              mock_selector: mock.Mock) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.config = proxy.ProtocolConfig()
        self.plugin = mock.MagicMock()

        self.mock_fromfd = mock_fromfd
        self.mock_selector = mock_selector

        plugin = get_plugin_by_test_name(self._testMethodName)

        self.config.plugins = {
            b'ProtocolHandlerPlugin': [proxy.HttpProxyPlugin],
            b'HttpProxyBasePlugin': [plugin],
        }
        self._conn = mock_fromfd.return_value
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=self.config)
        self.proxy.initialize()

    @mock.patch('proxy.TcpServerConnection')
    def test_modify_post_data_plugin(self, mock_server_conn: mock.Mock) -> None:
        original = b'{"key": "value"}'
        modified = b'{"key": "modified"}'

        self._conn.recv.return_value = proxy.build_http_request(
            b'POST', b'http://httpbin.org/post',
            headers={
                b'Host': b'httpbin.org',
                b'Content-Type': b'application/x-www-form-urlencoded',
                b'Content-Length': proxy.bytes_(len(original)),
            },
            body=original
        )
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]

        self.proxy.run_once()
        mock_server_conn.assert_called_with('httpbin.org', 80)
        mock_server_conn.return_value.queue.assert_called_with(
            proxy.build_http_request(
                b'POST', b'/post',
                headers={
                    b'Host': b'httpbin.org',
                    b'Content-Length': proxy.bytes_(len(modified)),
                    b'Content-Type': b'application/json',
                    b'Via': b'1.1 %s' % proxy.PROXY_AGENT_HEADER_VALUE,
                },
                body=modified
            )
        )

    @mock.patch('proxy.TcpServerConnection')
    def test_proposed_rest_api_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        path = b'/v1/users/'
        self._conn.recv.return_value = proxy.build_http_request(
            b'GET', b'http://%s%s' % (plugin_examples.ProposedRestApiPlugin.API_SERVER, path),
            headers={
                b'Host': plugin_examples.ProposedRestApiPlugin.API_SERVER,
            }
        )
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]
        self.proxy.run_once()

        mock_server_conn.assert_not_called()
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.build_http_response(
                proxy.httpStatusCodes.OK, reason=b'OK',
                headers={b'Content-Type': b'application/json'},
                body=proxy.bytes_(json.dumps(plugin_examples.ProposedRestApiPlugin.REST_API_SPEC[path]))
            ))

    @mock.patch('proxy.TcpServerConnection')
    def test_redirect_to_custom_server_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        request = proxy.build_http_request(
            b'GET', b'http://example.org/get',
            headers={
                b'Host': b'example.org',
            }
        )
        self._conn.recv.return_value = request
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]
        self.proxy.run_once()

        upstream = urlparse.urlsplit(
            plugin_examples.RedirectToCustomServerPlugin.UPSTREAM_SERVER)
        mock_server_conn.assert_called_with('localhost', 8899)
        mock_server_conn.return_value.queue.assert_called_with(
            proxy.build_http_request(
                b'GET', upstream.path,
                headers={
                    b'Host': upstream.netloc,
                    b'Via': b'1.1 %s' % proxy.PROXY_AGENT_HEADER_VALUE,
                }
            )
        )

    @mock.patch('proxy.TcpServerConnection')
    def test_filter_by_upstream_host_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        request = proxy.build_http_request(
            b'GET', b'http://google.com/',
            headers={
                b'Host': b'google.com',
            }
        )
        self._conn.recv.return_value = request
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]
        self.proxy.run_once()

        mock_server_conn.assert_not_called()
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.build_http_response(
                proxy.httpStatusCodes.I_AM_A_TEAPOT,
                reason=b'I\'m a tea pot',
                headers={
                    proxy.PROXY_AGENT_HEADER_KEY: proxy.PROXY_AGENT_HEADER_VALUE
                },
            )
        )

    @mock.patch('proxy.TcpServerConnection')
    def test_cache_responses_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        pass

    @mock.patch('proxy.TcpServerConnection')
    def test_man_in_the_middle_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        request = proxy.build_http_request(
            b'GET', b'http://super.secure/',
            headers={
                b'Host': b'super.secure',
            }
        )
        self._conn.recv.return_value = request

        server = mock_server_conn.return_value
        server.connect.return_value = True

        def has_buffer() -> bool:
            return cast(bool, server.queue.called)

        def closed() -> bool:
            return not server.connect.called

        server.has_buffer.side_effect = has_buffer
        type(server).closed = mock.PropertyMock(side_effect=closed)

        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)],
            [(selectors.SelectorKey(
                fileobj=server.connection,
                fd=server.connection.fileno,
                events=selectors.EVENT_WRITE,
                data=None), selectors.EVENT_WRITE)],
            [(selectors.SelectorKey(
                fileobj=server.connection,
                fd=server.connection.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]

        # Client read
        self.proxy.run_once()
        mock_server_conn.assert_called_with('super.secure', 80)
        server.connect.assert_called_once()
        queued_request = \
            proxy.build_http_request(
                b'GET', b'/',
                headers={
                    b'Host': b'super.secure',
                    b'Via': b'1.1 %s' % proxy.PROXY_AGENT_HEADER_VALUE
                }
            )
        server.queue.assert_called_once_with(queued_request)

        # Server write
        self.proxy.run_once()
        server.flush.assert_called_once()

        # Server read
        server.recv.return_value = \
            proxy.build_http_response(
                proxy.httpStatusCodes.OK,
                reason=b'OK', body=b'Original Response From Upstream')
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.build_http_response(
                proxy.httpStatusCodes.OK,
                reason=b'OK', body=b'Hello from man in the middle')
        )


class TestHttpProxyTlsInterception(unittest.TestCase):

    @mock.patch('ssl.wrap_socket')
    @mock.patch('ssl.create_default_context')
    @mock.patch('proxy.TcpServerConnection')
    @mock.patch('subprocess.Popen')
    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def test_e2e(
            self,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
            mock_popen: mock.Mock,
            mock_server_conn: mock.Mock,
            mock_ssl_context: mock.Mock,
            mock_ssl_wrap: mock.Mock) -> None:
        host, port = uuid.uuid4().hex, 443
        netloc = '{0}:{1}'.format(host, port)

        self.mock_fromfd = mock_fromfd
        self.mock_selector = mock_selector
        self.mock_popen = mock_popen
        self.mock_server_conn = mock_server_conn
        self.mock_ssl_context = mock_ssl_context
        self.mock_ssl_wrap = mock_ssl_wrap

        ssl_connection = mock.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_context.return_value.wrap_socket.return_value = ssl_connection
        self.mock_ssl_wrap.return_value = mock.MagicMock(spec=ssl.SSLSocket)
        plain_connection = mock.MagicMock(spec=socket.socket)

        def mock_connection() -> Any:
            if self.mock_ssl_context.return_value.wrap_socket.called:
                return ssl_connection
            return plain_connection

        type(self.mock_server_conn.return_value).connection = \
            mock.PropertyMock(side_effect=mock_connection)

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.config = proxy.ProtocolConfig(
            ca_cert_file='ca-cert.pem',
            ca_key_file='ca-key.pem',
            ca_signing_key_file='ca-signing-key.pem',
        )
        self.plugin = mock.MagicMock()
        self.proxy_plugin = mock.MagicMock()
        self.config.plugins = {
            b'ProtocolHandlerPlugin': [self.plugin, proxy.HttpProxyPlugin],
            b'HttpProxyBasePlugin': [self.proxy_plugin],
        }
        self._conn = mock_fromfd.return_value
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=self.config)
        self.proxy.initialize()

        self.plugin.assert_called()
        self.assertEqual(self.plugin.call_args[0][0], self.config)
        self.assertEqual(self.plugin.call_args[0][1].connection, self._conn)
        self.proxy_plugin.assert_called()
        self.assertEqual(self.proxy_plugin.call_args[0][0], self.config)
        self.assertEqual(self.proxy_plugin.call_args[0][1].connection, self._conn)

        connect_request = proxy.build_http_request(
            proxy.httpMethods.CONNECT, proxy.bytes_(netloc),
            headers={
                b'Host': proxy.bytes_(netloc),
            })
        self._conn.recv.return_value = connect_request

        # Prepare mocked ProtocolHandlerPlugin
        self.plugin.return_value.get_descriptors.return_value = ([], [])
        self.plugin.return_value.write_to_descriptors.return_value = False
        self.plugin.return_value.read_from_descriptors.return_value = False
        self.plugin.return_value.on_client_data.side_effect = lambda raw: raw
        self.plugin.return_value.on_request_complete.return_value = False
        self.plugin.return_value.on_response_chunk.side_effect = lambda chunk: chunk
        self.plugin.return_value.on_client_connection_close.return_value = None

        # Prepare mocked HttpProxyBasePlugin
        self.proxy_plugin.return_value.before_upstream_connection.side_effect = lambda r: r
        self.proxy_plugin.return_value.handle_client_request.side_effect = lambda r: r

        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]
        self.proxy.run_once()

        # Assert our mocked plugins invocations
        self.plugin.return_value.get_descriptors.assert_called()
        self.plugin.return_value.write_to_descriptors.assert_called_with([])
        self.plugin.return_value.on_client_data.assert_called_with(connect_request)
        self.plugin.return_value.on_request_complete.assert_called()
        self.plugin.return_value.read_from_descriptors.assert_called_with([self._conn])
        self.proxy_plugin.return_value.before_upstream_connection.assert_called()
        self.proxy_plugin.return_value.handle_client_request.assert_called()

        self.mock_server_conn.assert_called_with(host, port)
        self.mock_server_conn.return_value.connection.setblocking.assert_called_with(False)

        self.mock_ssl_context.assert_called_with(ssl.Purpose.SERVER_AUTH)
        # self.assertEqual(self.mock_ssl_context.return_value.options,
        #                  ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        self.assertEqual(plain_connection.setblocking.call_count, 2)
        self.mock_ssl_context.return_value.wrap_socket.assert_called_with(
            plain_connection, server_hostname=host)
        # TODO: Assert Popen arguments, piping, success condition
        self.assertEqual(self.mock_popen.call_count, 2)
        self.assertEqual(ssl_connection.setblocking.call_count, 1)
        self.assertEqual(self.mock_server_conn.return_value._conn, ssl_connection)
        self._conn.send.assert_called_with(proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        assert self.config.ca_cert_dir is not None
        self.mock_ssl_wrap.assert_called_with(
            self._conn,
            server_side=True,
            keyfile=self.config.ca_signing_key_file,
            certfile=proxy.HttpProxyPlugin.generated_cert_file_path(
                self.config.ca_cert_dir, host)
        )
        self.assertEqual(self._conn.setblocking.call_count, 2)
        self.assertEqual(self.proxy.client.connection, self.mock_ssl_wrap.return_value)

        # Assert connection references for all other plugins is updated
        self.assertEqual(self.plugin.return_value.client._conn, self.mock_ssl_wrap.return_value)
        self.assertEqual(self.proxy_plugin.return_value.client._conn, self.mock_ssl_wrap.return_value)


class TestHttpProxyPluginExamplesWithTlsInterception(unittest.TestCase):

    @mock.patch('ssl.wrap_socket')
    @mock.patch('ssl.create_default_context')
    @mock.patch('proxy.TcpServerConnection')
    @mock.patch('subprocess.Popen')
    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self,
              mock_fromfd: mock.Mock,
              mock_selector: mock.Mock,
              mock_popen: mock.Mock,
              mock_server_conn: mock.Mock,
              mock_ssl_context: mock.Mock,
              mock_ssl_wrap: mock.Mock) -> None:
        self.mock_fromfd = mock_fromfd
        self.mock_selector = mock_selector
        self.mock_popen = mock_popen
        self.mock_server_conn = mock_server_conn
        self.mock_ssl_context = mock_ssl_context
        self.mock_ssl_wrap = mock_ssl_wrap

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.config = proxy.ProtocolConfig(
            ca_cert_file='ca-cert.pem',
            ca_key_file='ca-key.pem',
            ca_signing_key_file='ca-signing-key.pem',)
        self.plugin = mock.MagicMock()

        plugin = get_plugin_by_test_name(self._testMethodName)

        self.config.plugins = {
            b'ProtocolHandlerPlugin': [proxy.HttpProxyPlugin],
            b'HttpProxyBasePlugin': [plugin],
        }
        self._conn = mock.MagicMock(spec=socket.socket)
        mock_fromfd.return_value = self._conn
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=self.config)
        self.proxy.initialize()

        self.server = self.mock_server_conn.return_value

        self.server_ssl_connection = mock.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_context.return_value.wrap_socket.return_value = self.server_ssl_connection
        self.client_ssl_connection = mock.MagicMock(spec=ssl.SSLSocket)
        self.mock_ssl_wrap.return_value = self.client_ssl_connection

        def has_buffer() -> bool:
            return cast(bool, self.server.queue.called)

        def closed() -> bool:
            return not self.server.connect.called

        def mock_connection() -> Any:
            if self.mock_ssl_context.return_value.wrap_socket.called:
                return self.server_ssl_connection
            return self._conn

        self.server.has_buffer.side_effect = has_buffer
        type(self.server).closed = mock.PropertyMock(side_effect=closed)
        type(self.server).connection = mock.PropertyMock(side_effect=mock_connection)

        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)],
            [(selectors.SelectorKey(
                fileobj=self.client_ssl_connection,
                fd=self.client_ssl_connection.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)],
            [(selectors.SelectorKey(
                fileobj=self.server_ssl_connection,
                fd=self.server_ssl_connection.fileno,
                events=selectors.EVENT_WRITE,
                data=None), selectors.EVENT_WRITE)],
            [(selectors.SelectorKey(
                fileobj=self.server_ssl_connection,
                fd=self.server_ssl_connection.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]

        # Connect
        def send(raw: bytes) -> int:
            return len(raw)

        self._conn.send.side_effect = send
        self._conn.recv.return_value = proxy.build_http_request(
            proxy.httpMethods.CONNECT, b'uni.corn:443'
        )
        self.proxy.run_once()

        self.mock_popen.assert_called()
        self.mock_server_conn.assert_called_once_with('uni.corn', 443)
        self.server.connect.assert_called()
        self.assertEqual(self.proxy.client.connection, self.client_ssl_connection)
        self.assertEqual(self.server.connection, self.server_ssl_connection)
        self._conn.send.assert_called_with(
            proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT
        )
        self.assertEqual(self.proxy.client.buffer, b'')

    def test_modify_post_data_plugin(self) -> None:
        original = b'{"key": "value"}'
        modified = b'{"key": "modified"}'
        self.client_ssl_connection.recv.return_value = proxy.build_http_request(
            b'POST', b'/',
            headers={
                b'Host': b'uni.corn',
                b'Content-Type': b'application/x-www-form-urlencoded',
                b'Content-Length': proxy.bytes_(len(original)),
            },
            body=original
        )
        self.proxy.run_once()
        self.server.queue.assert_called_with(
            proxy.build_http_request(
                b'POST', b'/',
                headers={
                    b'Host': b'uni.corn',
                    b'Content-Length': proxy.bytes_(len(modified)),
                    b'Content-Type': b'application/json',
                },
                body=modified
            )
        )

    @mock.patch('proxy.TcpServerConnection')
    def test_cache_responses_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        pass

    @mock.patch('proxy.TcpServerConnection')
    def test_man_in_the_middle_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        request = proxy.build_http_request(
            b'GET', b'/',
            headers={
                b'Host': b'uni.corn',
            }
        )
        self.client_ssl_connection.recv.return_value = request

        # Client read
        self.proxy.run_once()
        self.server.queue.assert_called_once_with(request)

        # Server write
        self.proxy.run_once()
        self.server.flush.assert_called_once()

        # Server read
        self.server.recv.return_value = \
            proxy.build_http_response(
                proxy.httpStatusCodes.OK,
                reason=b'OK', body=b'Original Response From Upstream')
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.build_http_response(
                proxy.httpStatusCodes.OK,
                reason=b'OK', body=b'Hello from man in the middle')
        )


class TestHttpRequestRejected(unittest.TestCase):

    def setUp(self) -> None:
        self.request = proxy.HttpParser(proxy.httpParserTypes.REQUEST_PARSER)

    def test_empty_response(self) -> None:
        e = proxy.HttpRequestRejected()
        self.assertEqual(e.response(self.request), None)

    def test_status_code_response(self) -> None:
        e = proxy.HttpRequestRejected(status_code=200, reason=b'OK')
        self.assertEqual(e.response(self.request), proxy.CRLF.join([
            b'HTTP/1.1 200 OK',
            proxy.PROXY_AGENT_HEADER,
            proxy.CRLF
        ]))

    def test_body_response(self) -> None:
        e = proxy.HttpRequestRejected(
            status_code=404, reason=b'NOT FOUND',
            body=b'Nothing here')
        self.assertEqual(e.response(self.request), proxy.CRLF.join([
            b'HTTP/1.1 404 NOT FOUND',
            proxy.PROXY_AGENT_HEADER,
            b'Content-Length: 12',
            proxy.CRLF,
            b'Nothing here'
        ]))


class TestMain(unittest.TestCase):

    @staticmethod
    def mock_default_args(mock_args: mock.Mock) -> None:
        mock_args.version = False
        mock_args.cert_file = proxy.DEFAULT_CERT_FILE
        mock_args.key_file = proxy.DEFAULT_KEY_FILE
        mock_args.ca_key_file = proxy.DEFAULT_CA_KEY_FILE
        mock_args.ca_cert_file = proxy.DEFAULT_CA_CERT_FILE
        mock_args.ca_signing_key_file = proxy.DEFAULT_CA_SIGNING_KEY_FILE
        mock_args.pid_file = proxy.DEFAULT_PID_FILE
        mock_args.log_file = proxy.DEFAULT_LOG_FILE
        mock_args.log_level = proxy.DEFAULT_LOG_LEVEL
        mock_args.log_format = proxy.DEFAULT_LOG_FORMAT
        mock_args.basic_auth = proxy.DEFAULT_BASIC_AUTH
        mock_args.hostname = proxy.DEFAULT_IPV6_HOSTNAME
        mock_args.port = proxy.DEFAULT_PORT
        mock_args.num_workers = proxy.DEFAULT_NUM_WORKERS
        mock_args.disable_http_proxy = proxy.DEFAULT_DISABLE_HTTP_PROXY
        mock_args.enable_web_server = proxy.DEFAULT_ENABLE_WEB_SERVER
        mock_args.pac_file = proxy.DEFAULT_PAC_FILE
        mock_args.plugins = proxy.DEFAULT_PLUGINS
        mock_args.server_recvbuf_size = proxy.DEFAULT_SERVER_RECVBUF_SIZE
        mock_args.client_recvbuf_size = proxy.DEFAULT_CLIENT_RECVBUF_SIZE
        mock_args.open_file_limit = proxy.DEFAULT_OPEN_FILE_LIMIT
        mock_args.enable_static_server = proxy.DEFAULT_ENABLE_STATIC_SERVER
        mock_args.enable_devtools = proxy.DEFAULT_ENABLE_DEVTOOLS
        mock_args.devtools_event_queue = None
        mock_args.devtools_ws_path = proxy.DEFAULT_DEVTOOLS_WS_PATH
        mock_args.timeout = proxy.DEFAULT_TIMEOUT

    @mock.patch('time.sleep')
    @mock.patch('proxy.load_plugins')
    @mock.patch('proxy.init_parser')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.ProtocolConfig')
    @mock.patch('proxy.AcceptorPool')
    @mock.patch('proxy.logging.basicConfig')
    def test_init_with_no_arguments(
            self,
            mock_logging_config: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_protocol_config: mock.Mock,
            mock_set_open_file_limit: mock.Mock,
            mock_init_parser: mock.Mock,
            mock_load_plugins: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()

        mock_args = mock_init_parser.return_value.parse_args.return_value
        self.mock_default_args(mock_args)
        proxy.main([])

        mock_init_parser.assert_called()
        mock_init_parser.return_value.parse_args.called_with([])

        mock_load_plugins.assert_called_with(b'proxy.HttpProxyPlugin,')
        mock_logging_config.assert_called_with(
            level=logging.INFO,
            format=proxy.DEFAULT_LOG_FORMAT
        )
        mock_set_open_file_limit.assert_called_with(mock_args.open_file_limit)

        mock_protocol_config.assert_called_with(
            auth_code=mock_args.basic_auth,
            backlog=mock_args.backlog,
            ca_cert_dir=mock_args.ca_cert_dir,
            ca_cert_file=mock_args.ca_cert_file,
            ca_key_file=mock_args.ca_key_file,
            ca_signing_key_file=mock_args.ca_signing_key_file,
            certfile=mock_args.cert_file,
            client_recvbuf_size=mock_args.client_recvbuf_size,
            hostname=mock_args.hostname,
            keyfile=mock_args.key_file,
            num_workers=multiprocessing.cpu_count(),
            pac_file=mock_args.pac_file,
            pac_file_url_path=mock_args.pac_file_url_path,
            port=mock_args.port,
            server_recvbuf_size=mock_args.server_recvbuf_size,
            disable_headers=[
                header.lower() for header in proxy.bytes_(
                    mock_args.disable_headers).split(proxy.COMMA) if header.strip() != b''],
            static_server_dir=mock_args.static_server_dir,
            enable_static_server=mock_args.enable_static_server,
            devtools_event_queue=None,
            devtools_ws_path=proxy.DEFAULT_DEVTOOLS_WS_PATH,
            timeout=proxy.DEFAULT_TIMEOUT
        )

        mock_acceptor_pool.assert_called_with(
            hostname=mock_protocol_config.return_value.hostname,
            port=mock_protocol_config.return_value.port,
            backlog=mock_protocol_config.return_value.backlog,
            num_workers=mock_protocol_config.return_value.num_workers,
            work_klass=proxy.ProtocolHandler,
            config=mock_protocol_config.return_value,
        )
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_acceptor_pool.return_value.shutdown.assert_called()
        mock_sleep.assert_called_with(1)

    @mock.patch('time.sleep')
    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.init_parser')
    @mock.patch('proxy.AcceptorPool')
    def test_pid_file_is_written_and_removed(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_init_parser: mock.Mock,
            mock_open: mock.Mock,
            mock_exists: mock.Mock,
            mock_remove: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        pid_file = get_temp_file('proxy.pid')
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_init_parser.return_value.parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.pid_file = pid_file
        proxy.main(['--pid-file', pid_file])
        mock_init_parser.assert_called()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            proxy.bytes_(os.getpid()))
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('time.sleep')
    @mock.patch('proxy.ProtocolConfig')
    @mock.patch('proxy.AcceptorPool')
    def test_basic_auth(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_protocol_config: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        proxy.main(['--basic-auth', 'user:pass'])
        config = mock_protocol_config.return_value
        mock_acceptor_pool.assert_called_with(
            hostname=config.hostname,
            port=config.port,
            backlog=config.backlog,
            num_workers=config.num_workers,
            work_klass=proxy.ProtocolHandler,
            config=config)
        self.assertEqual(mock_protocol_config.call_args[1]['auth_code'], b'Basic dXNlcjpwYXNz')

    @mock.patch('builtins.print')
    def test_main_version(
            self,
            mock_print: mock.Mock) -> None:
        with self.assertRaises(SystemExit):
            proxy.main(['--version'])
            mock_print.assert_called_with(proxy.text_(proxy.version))

    @mock.patch('time.sleep')
    @mock.patch('builtins.print')
    @mock.patch('proxy.AcceptorPool')
    @mock.patch('proxy.is_py3')
    def test_main_py3_runs(
            self,
            mock_is_py3: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_print: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_is_py3.return_value = True
        proxy.main([])
        mock_is_py3.assert_called()
        mock_print.assert_not_called()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.is_py3')
    def test_main_py2_exit(
            self,
            mock_is_py3: mock.Mock,
            mock_print: mock.Mock) -> None:
        proxy.UNDER_TEST = False
        mock_is_py3.return_value = False
        with self.assertRaises(SystemExit):
            proxy.main([])
            mock_print.assert_called_with('DEPRECATION')
        mock_is_py3.assert_called()


@unittest.skipIf(
    os.name == 'nt',
    'Open file limit tests disabled for Windows')
class TestSetOpenFileLimit(unittest.TestCase):

    @mock.patch('resource.getrlimit', return_value=(128, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock) -> None:
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_called_with(resource.RLIMIT_NOFILE, (256, 1024))

    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock) -> None:
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()

    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called_coz_upper_bound_check(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock) -> None:
        proxy.set_open_file_limit(1024)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()


if __name__ == '__main__':
    proxy.UNDER_TEST = True
    unittest.main()
