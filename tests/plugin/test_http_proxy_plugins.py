# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import pytest
import selectors

from pathlib import Path
from unittest import mock
from typing import cast, Any
from urllib import parse as urlparse
from pytest_mock import MockerFixture

from proxy.common.flag import FlagParser
from proxy.core.connection import TcpClientConnection
from proxy.http import HttpProtocolHandler
from proxy.http import httpStatusCodes
from proxy.http.proxy import HttpProxyPlugin
from proxy.common.utils import build_http_request, bytes_, build_http_response
from proxy.common.constants import PROXY_AGENT_HEADER_VALUE, DEFAULT_HTTP_PORT
from proxy.plugin import ProposedRestApiPlugin, RedirectToCustomServerPlugin

from .utils import get_plugin_by_test_name

from ..test_assertions import Assertions


class TestHttpProxyPluginExamples(Assertions):

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, request: Any, mocker: MockerFixture) -> None:
        self.mock_fromfd = mocker.patch('socket.fromfd')
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_server_conn = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
        )

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        adblock_json_path = Path(
            __file__,
        ).parent.parent.parent / "proxy" / "plugin" / "adblock.json"
        self.flags = FlagParser.initialize(
            input_args=[
                "--filtered-url-regex-config",
                str(adblock_json_path),
            ],
            threaded=True,
        )
        self.plugin = mock.MagicMock()

        plugin = get_plugin_by_test_name(request.param)

        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
            b'HttpProxyBasePlugin': [plugin],
        }
        self._conn = self.mock_fromfd.return_value
        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        "_setUp",
        (
            ('test_modify_post_data_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_modify_post_data_plugin(self) -> None:
        original = b'{"key": "value"}'
        modified = b'{"key": "modified"}'

        self._conn.recv.return_value = build_http_request(
            b'POST', b'http://httpbin.org/post',
            headers={
                b'Host': b'httpbin.org',
                b'Content-Type': b'application/x-www-form-urlencoded',
                b'Content-Length': bytes_(len(original)),
            },
            body=original,
        )
        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]

        await self.protocol_handler._run_once()
        self.mock_server_conn.assert_called_with(
            'httpbin.org', DEFAULT_HTTP_PORT,
        )
        self.mock_server_conn.return_value.queue.assert_called_with(
            build_http_request(
                b'POST', b'/post',
                headers={
                    b'Host': b'httpbin.org',
                    b'Content-Length': bytes_(len(modified)),
                    b'Content-Type': b'application/json',
                    b'Via': b'1.1 %s' % PROXY_AGENT_HEADER_VALUE,
                },
                body=modified,
            ),
        )

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        "_setUp",
        (
            ('test_proposed_rest_api_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_proposed_rest_api_plugin(self) -> None:
        path = b'/v1/users/'
        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://%s%s' % (
                ProposedRestApiPlugin.API_SERVER, path,
            ),
            headers={
                b'Host': ProposedRestApiPlugin.API_SERVER,
            },
        )
        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]
        await self.protocol_handler._run_once()

        self.mock_server_conn.assert_not_called()
        self.assertEqual(
            self.protocol_handler.work.buffer[0].tobytes(),
            build_http_response(
                httpStatusCodes.OK, reason=b'OK',
                headers={b'Content-Type': b'application/json'},
                body=bytes_(
                    json.dumps(
                        ProposedRestApiPlugin.REST_API_SPEC[path],
                    ),
                ),
            ),
        )

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        "_setUp",
        (
            ('test_redirect_to_custom_server_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_redirect_to_custom_server_plugin(self) -> None:
        request = build_http_request(
            b'GET', b'http://example.org/get',
            headers={
                b'Host': b'example.org',
            },
        )
        self._conn.recv.return_value = request
        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]
        await self.protocol_handler._run_once()

        upstream = urlparse.urlsplit(
            RedirectToCustomServerPlugin.UPSTREAM_SERVER,
        )
        self.mock_server_conn.assert_called_with('localhost', 8899)
        self.mock_server_conn.return_value.queue.assert_called_with(
            build_http_request(
                b'GET', upstream.path,
                headers={
                    b'Host': upstream.netloc,
                    b'Via': b'1.1 %s' % PROXY_AGENT_HEADER_VALUE,
                },
            ),
        )

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        "_setUp",
        (
            ('test_filter_by_upstream_host_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_filter_by_upstream_host_plugin(self) -> None:
        request = build_http_request(
            b'GET', b'http://facebook.com/',
            headers={
                b'Host': b'facebook.com',
            },
        )
        self._conn.recv.return_value = request
        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]
        await self.protocol_handler._run_once()

        self.mock_server_conn.assert_not_called()
        self.assertEqual(
            self.protocol_handler.work.buffer[0].tobytes(),
            build_http_response(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b'I\'m a tea pot',
                headers={
                    b'Connection': b'close',
                },
            ),
        )

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        "_setUp",
        (
            ('test_man_in_the_middle_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_man_in_the_middle_plugin(self) -> None:
        request = build_http_request(
            b'GET', b'http://super.secure/',
            headers={
                b'Host': b'super.secure',
            },
        )
        self._conn.recv.return_value = request

        server = self.mock_server_conn.return_value
        server.connect.return_value = True

        def has_buffer() -> bool:
            return cast(bool, server.queue.called)

        def closed() -> bool:
            return not server.connect.called

        server.has_buffer.side_effect = has_buffer
        type(server).closed = mock.PropertyMock(side_effect=closed)

        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
            [(
                selectors.SelectorKey(
                    fileobj=server.connection.fileno(),
                    fd=server.connection.fileno(),
                    events=selectors.EVENT_WRITE,
                    data=None,
                ),
                selectors.EVENT_WRITE,
            )],
            [(
                selectors.SelectorKey(
                    fileobj=server.connection.fileno(),
                    fd=server.connection.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]

        # Client read
        await self.protocol_handler._run_once()
        self.mock_server_conn.assert_called_with(
            'super.secure', DEFAULT_HTTP_PORT,
        )
        server.connect.assert_called_once()
        queued_request = \
            build_http_request(
                b'GET', b'/',
                headers={
                    b'Host': b'super.secure',
                    b'Via': b'1.1 %s' % PROXY_AGENT_HEADER_VALUE,
                },
            )
        server.queue.assert_called_once_with(queued_request)

        # Server write
        await self.protocol_handler._run_once()
        server.flush.assert_called_once()

        # Server read
        server.recv.return_value = \
            build_http_response(
                httpStatusCodes.OK,
                reason=b'OK', body=b'Original Response From Upstream',
            )
        await self.protocol_handler._run_once()
        self.assertEqual(
            self.protocol_handler.work.buffer[0].tobytes(),
            build_http_response(
                httpStatusCodes.OK,
                reason=b'OK', body=b'Hello from man in the middle',
            ),
        )

    @pytest.mark.asyncio    # type: ignore[misc]
    @pytest.mark.parametrize(
        "_setUp",
        (
            ('test_filter_by_url_regex_plugin'),
        ),
        indirect=True,
    )   # type: ignore[misc]
    async def test_filter_by_url_regex_plugin(self) -> None:
        request = build_http_request(
            b'GET', b'http://www.facebook.com/tr/',
            headers={
                b'Host': b'www.facebook.com',
            },
        )
        self._conn.recv.return_value = request
        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]
        await self.protocol_handler._run_once()

        self.assertEqual(
            self.protocol_handler.work.buffer[0].tobytes(),
            build_http_response(
                status_code=httpStatusCodes.NOT_FOUND,
                reason=b'Blocked',
                headers={b'Connection': b'close'},
            ),
        )
