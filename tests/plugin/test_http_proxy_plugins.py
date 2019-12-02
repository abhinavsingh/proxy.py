# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
import selectors
import json

from urllib import parse as urlparse
from unittest import mock
from typing import cast

from proxy.common.flags import Flags
from proxy.core.connection import TcpClientConnection
from proxy.http.handler import HttpProtocolHandler
from proxy.http.proxy import HttpProxyPlugin
from proxy.common.utils import build_http_request, bytes_, build_http_response
from proxy.common.constants import PROXY_AGENT_HEADER_VALUE, DEFAULT_HTTP_PORT
from proxy.http.codes import httpStatusCodes

from proxy.plugin import ProposedRestApiPlugin, RedirectToCustomServerPlugin

from .utils import get_plugin_by_test_name


class TestHttpProxyPluginExamples(unittest.TestCase):

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    def setUp(self,
              mock_fromfd: mock.Mock,
              mock_selector: mock.Mock) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.flags = Flags()
        self.plugin = mock.MagicMock()

        self.mock_fromfd = mock_fromfd
        self.mock_selector = mock_selector

        plugin = get_plugin_by_test_name(self._testMethodName)

        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
            b'HttpProxyBasePlugin': [plugin],
        }
        self._conn = mock_fromfd.return_value
        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr),
            flags=self.flags)
        self.protocol_handler.initialize()

    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_modify_post_data_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        original = b'{"key": "value"}'
        modified = b'{"key": "modified"}'

        self._conn.recv.return_value = build_http_request(
            b'POST', b'http://httpbin.org/post',
            headers={
                b'Host': b'httpbin.org',
                b'Content-Type': b'application/x-www-form-urlencoded',
                b'Content-Length': bytes_(len(original)),
            },
            body=original
        )
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]

        self.protocol_handler.run_once()
        mock_server_conn.assert_called_with('httpbin.org', DEFAULT_HTTP_PORT)
        mock_server_conn.return_value.queue.assert_called_with(
            build_http_request(
                b'POST', b'/post',
                headers={
                    b'Host': b'httpbin.org',
                    b'Content-Length': bytes_(len(modified)),
                    b'Content-Type': b'application/json',
                    b'Via': b'1.1 %s' % PROXY_AGENT_HEADER_VALUE,
                },
                body=modified
            )
        )

    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_proposed_rest_api_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        path = b'/v1/users/'
        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://%s%s' % (
                ProposedRestApiPlugin.API_SERVER, path),
            headers={
                b'Host': ProposedRestApiPlugin.API_SERVER,
            }
        )
        self.mock_selector.return_value.select.side_effect = [
            [(selectors.SelectorKey(
                fileobj=self._conn,
                fd=self._conn.fileno,
                events=selectors.EVENT_READ,
                data=None), selectors.EVENT_READ)], ]
        self.protocol_handler.run_once()

        mock_server_conn.assert_not_called()
        self.assertEqual(
            self.protocol_handler.client.buffer[0].tobytes(),
            build_http_response(
                httpStatusCodes.OK, reason=b'OK',
                headers={b'Content-Type': b'application/json'},
                body=bytes_(
                    json.dumps(
                        ProposedRestApiPlugin.REST_API_SPEC[path]))
            ))

    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_redirect_to_custom_server_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        request = build_http_request(
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
        self.protocol_handler.run_once()

        upstream = urlparse.urlsplit(
            RedirectToCustomServerPlugin.UPSTREAM_SERVER)
        mock_server_conn.assert_called_with('localhost', 8899)
        mock_server_conn.return_value.queue.assert_called_with(
            build_http_request(
                b'GET', upstream.path,
                headers={
                    b'Host': upstream.netloc,
                    b'Via': b'1.1 %s' % PROXY_AGENT_HEADER_VALUE,
                }
            )
        )

    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_filter_by_upstream_host_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        request = build_http_request(
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
        self.protocol_handler.run_once()

        mock_server_conn.assert_not_called()
        self.assertEqual(
            self.protocol_handler.client.buffer[0].tobytes(),
            build_http_response(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b'I\'m a tea pot',
                headers={
                    b'Connection': b'close'
                },
            )
        )

    @mock.patch('proxy.http.proxy.server.TcpServerConnection')
    def test_man_in_the_middle_plugin(
            self, mock_server_conn: mock.Mock) -> None:
        request = build_http_request(
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
        self.protocol_handler.run_once()
        mock_server_conn.assert_called_with('super.secure', DEFAULT_HTTP_PORT)
        server.connect.assert_called_once()
        queued_request = \
            build_http_request(
                b'GET', b'/',
                headers={
                    b'Host': b'super.secure',
                    b'Via': b'1.1 %s' % PROXY_AGENT_HEADER_VALUE
                }
            )
        server.queue.assert_called_once_with(queued_request)

        # Server write
        self.protocol_handler.run_once()
        server.flush.assert_called_once()

        # Server read
        server.recv.return_value = \
            build_http_response(
                httpStatusCodes.OK,
                reason=b'OK', body=b'Original Response From Upstream')
        self.protocol_handler.run_once()
        self.assertEqual(
            self.protocol_handler.client.buffer[0].tobytes(),
            build_http_response(
                httpStatusCodes.OK,
                reason=b'OK', body=b'Hello from man in the middle')
        )
