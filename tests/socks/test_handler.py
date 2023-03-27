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

from pytest_mock import MockerFixture

from proxy.socks import SocksProtocolHandler, SocksClientConnection
from proxy.common.flag import FlagParser
from ..test_assertions import Assertions


class TestHttpProtocolHandlerWithoutServerMock(Assertions):

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture) -> None:
        self.mock_socket = mocker.patch('socket.socket')
        self.mock_socket_dup = mocker.patch('socket.dup', side_effect=lambda fd: fd)
        self.mock_selector = mocker.patch('selectors.DefaultSelector')

        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = self.mock_socket.return_value

        self.flags = FlagParser.initialize(threaded=True)

        self.handler = SocksProtocolHandler(
            SocksClientConnection(conn=self._conn, addr=self._addr),
            flags=self.flags,
        )
        self.handler.initialize()

    def test(self) -> None:
        self.assertEqual(1, 1)
