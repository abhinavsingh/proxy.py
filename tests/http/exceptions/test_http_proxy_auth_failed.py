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

from proxy.common.flag import FlagParser
from proxy.http.exception.proxy_auth_failed import ProxyAuthenticationFailed
from proxy.http import HttpProtocolHandler, httpHeaders
from proxy.core.connection import TcpClientConnection
from proxy.common.utils import build_http_request

from ...test_assertions import Assertions


class TestHttpProxyAuthFailed(Assertions):

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture) -> None:
        self.mock_fromfd = mocker.patch('socket.fromfd')
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_server_conn = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
        )

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self.flags = FlagParser.initialize(
            ["--basic-auth", "user:pass"], threaded=True,
        )
        self._conn = self.mock_fromfd.return_value
        self.protocol_handler = HttpProtocolHandler(
            TcpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_auth_fails_without_cred(self) -> None:
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
        self.assertEqual(self.protocol_handler.work.has_buffer(), True)
        self.assertEqual(
            self.protocol_handler.work.buffer[0], ProxyAuthenticationFailed.RESPONSE_PKT,
        )
        self._conn.send.assert_not_called()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_auth_fails_with_invalid_cred(self) -> None:
        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://upstream.host/not-found.html',
            headers={
                b'Host': b'upstream.host',
                httpHeaders.PROXY_AUTHORIZATION: b'Basic hello',
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
        self.assertEqual(self.protocol_handler.work.has_buffer(), True)
        self.assertEqual(
            self.protocol_handler.work.buffer[0], ProxyAuthenticationFailed.RESPONSE_PKT,
        )
        self._conn.send.assert_not_called()

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_auth_works_with_valid_cred(self) -> None:
        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://upstream.host/not-found.html',
            headers={
                b'Host': b'upstream.host',
                httpHeaders.PROXY_AUTHORIZATION: b'Basic dXNlcjpwYXNz',
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
        self.mock_server_conn.assert_called_once()
        self.assertEqual(self.protocol_handler.work.has_buffer(), False)

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_proxy_auth_works_with_mixed_case_basic_string(self) -> None:
        self._conn.recv.return_value = build_http_request(
            b'GET', b'http://upstream.host/not-found.html',
            headers={
                b'Host': b'upstream.host',
                httpHeaders.PROXY_AUTHORIZATION: b'bAsIc dXNlcjpwYXNz',
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
        self.mock_server_conn.assert_called_once()
        self.assertEqual(self.protocol_handler.work.has_buffer(), False)
