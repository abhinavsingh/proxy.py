# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import pytest
import selectors

from pytest_mock import MockerFixture

from proxy.common.constants import DEFAULT_HTTP_PORT
from proxy.common.flag import FlagParser
from proxy.core.connection import TcpClientConnection
from proxy.http.proxy import HttpProxyPlugin
from proxy.http import HttpProtocolHandler
from proxy.http.exception import HttpProtocolException
from proxy.common.utils import build_http_request


class TestHttpProxyPlugin:

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture) -> None:
        self.mock_server_conn = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
        )
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_fromfd = mocker.patch('socket.fromfd')

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.flags = FlagParser.initialize(threaded=True)
        self.plugin = mocker.MagicMock()
        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
            b'HttpProxyBasePlugin': [self.plugin],
        }
        self._conn = self.mock_fromfd.return_value
        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

    def test_proxy_plugin_not_initialized_unless_first_request_completes(self) -> None:
        self.plugin.assert_not_called()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_plugin_on_and_before_upstream_connection(self) -> None:
        self.plugin.return_value.write_to_descriptors.return_value = False
        self.plugin.return_value.read_from_descriptors.return_value = False
        self.plugin.return_value.before_upstream_connection.side_effect = lambda r: r
        self.plugin.return_value.handle_client_request.side_effect = lambda r: r
        self.plugin.return_value.resolve_dns.return_value = None, None

        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://upstream.host/not-found.html',
            headers={
                b'Host': b'upstream.host',
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

        self.mock_server_conn.assert_called_with(
            'upstream.host', DEFAULT_HTTP_PORT,
        )
        self.plugin.return_value.before_upstream_connection.assert_called()
        self.plugin.return_value.handle_client_request.assert_called()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_plugin_before_upstream_connection_can_teardown(self) -> None:
        self.plugin.return_value.write_to_descriptors.return_value = False
        self.plugin.return_value.read_from_descriptors.return_value = False
        self.plugin.return_value.before_upstream_connection.side_effect = HttpProtocolException()

        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://upstream.host/not-found.html',
            headers={
                b'Host': b'upstream.host',
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
        self.plugin.return_value.before_upstream_connection.assert_called()

    def test_proxy_plugin_plugins_can_teardown_from_write_to_descriptors(self) -> None:
        pass

    def test_proxy_plugin_retries_on_ssl_want_write_error(self) -> None:
        pass

    def test_proxy_plugin_broken_pipe_error_on_write_will_teardown(self) -> None:
        pass

    def test_proxy_plugin_plugins_can_teardown_from_read_from_descriptors(self) -> None:
        pass

    def test_proxy_plugin_retries_on_ssl_want_read_error(self) -> None:
        pass

    def test_proxy_plugin_timeout_error_on_read_will_teardown(self) -> None:
        pass

    def test_proxy_plugin_invokes_handle_pipeline_response(self) -> None:
        pass

    def test_proxy_plugin_invokes_on_access_log(self) -> None:
        pass

    def test_proxy_plugin_skips_server_teardown_when_client_closes_and_server_never_initialized(self) -> None:
        pass

    def test_proxy_plugin_invokes_handle_client_data(self) -> None:
        pass

    def test_proxy_plugin_handles_pipeline_response(self) -> None:
        pass

    def test_proxy_plugin_invokes_resolve_dns(self) -> None:
        pass

    def test_proxy_plugin_require_both_host_port_to_connect(self) -> None:
        pass
