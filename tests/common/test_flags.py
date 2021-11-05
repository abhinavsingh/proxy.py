# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Dict, List

import unittest
from unittest import mock

from proxy.common.constants import PLUGIN_HTTP_PROXY, PY2_DEPRECATION_MESSAGE
from proxy.common.flag import FlagParser
from proxy.common.utils import bytes_
from proxy.common.version import __version__
from proxy.http.proxy import HttpProxyPlugin
from proxy.plugin import CacheResponsesPlugin, FilterByUpstreamHostPlugin


class TestFlags(unittest.TestCase):
    def assert_plugins(self, expected: Dict[str, List[type]]) -> None:
        for k in expected:
            self.assertIn(k.encode(), self.flags.plugins)
            for p in expected[k]:
                self.assertIn(p, self.flags.plugins[k.encode()])
                self.assertEqual(
                    len([o for o in self.flags.plugins[k.encode()] if o == p]), 1,
                )

    def test_load_plugin_from_bytes(self) -> None:
        self.flags = FlagParser.initialize(
            [], plugins=[
                b'proxy.plugin.CacheResponsesPlugin',
            ],
        )
        self.assert_plugins({'HttpProxyBasePlugin': [CacheResponsesPlugin]})

    def test_load_plugins_from_bytes(self) -> None:
        self.flags = FlagParser.initialize(
            [], plugins=[
                b'proxy.plugin.CacheResponsesPlugin',
                b'proxy.plugin.FilterByUpstreamHostPlugin',
            ],
        )
        self.assert_plugins({
            'HttpProxyBasePlugin': [
                CacheResponsesPlugin,
                FilterByUpstreamHostPlugin,
            ],
        })

    def test_load_plugin_from_args(self) -> None:
        self.flags = FlagParser.initialize([
            '--plugins', 'proxy.plugin.CacheResponsesPlugin',
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [CacheResponsesPlugin]})

    def test_load_plugins_from_args(self) -> None:
        self.flags = FlagParser.initialize([
            '--plugins', 'proxy.plugin.CacheResponsesPlugin,proxy.plugin.FilterByUpstreamHostPlugin',
        ])
        self.assert_plugins({
            'HttpProxyBasePlugin': [
                CacheResponsesPlugin,
                FilterByUpstreamHostPlugin,
            ],
        })

    def test_load_plugin_from_class(self) -> None:
        self.flags = FlagParser.initialize(
            [], plugins=[
                CacheResponsesPlugin,
            ],
        )
        self.assert_plugins({'HttpProxyBasePlugin': [CacheResponsesPlugin]})

    def test_load_plugins_from_class(self) -> None:
        self.flags = FlagParser.initialize(
            [], plugins=[
                CacheResponsesPlugin,
                FilterByUpstreamHostPlugin,
            ],
        )
        self.assert_plugins({
            'HttpProxyBasePlugin': [
                CacheResponsesPlugin,
                FilterByUpstreamHostPlugin,
            ],
        })

    def test_load_plugins_from_bytes_and_class(self) -> None:
        self.flags = FlagParser.initialize(
            [], plugins=[
                CacheResponsesPlugin,
                b'proxy.plugin.FilterByUpstreamHostPlugin',
            ],
        )
        self.assert_plugins({
            'HttpProxyBasePlugin': [
                CacheResponsesPlugin,
                FilterByUpstreamHostPlugin,
            ],
        })

    def test_unique_plugin_from_bytes(self) -> None:
        self.flags = FlagParser.initialize(
            [], plugins=[
                bytes_(PLUGIN_HTTP_PROXY),
            ],
        )
        self.assert_plugins({
            'HttpProtocolHandlerPlugin': [
                HttpProxyPlugin,
            ],
        })

    def test_unique_plugin_from_args(self) -> None:
        self.flags = FlagParser.initialize([
            '--plugins', PLUGIN_HTTP_PROXY,
        ])
        self.assert_plugins({
            'HttpProtocolHandlerPlugin': [
                HttpProxyPlugin,
            ],
        })

    def test_unique_plugin_from_class(self) -> None:
        self.flags = FlagParser.initialize(
            [], plugins=[
                HttpProxyPlugin,
            ],
        )
        self.assert_plugins({
            'HttpProtocolHandlerPlugin': [
                HttpProxyPlugin,
            ],
        })

    def test_basic_auth_flag_is_base64_encoded(self) -> None:
        flags = FlagParser.initialize(['--basic-auth', 'user:pass'])
        self.assertEqual(flags.auth_code, b'dXNlcjpwYXNz')

    @mock.patch('builtins.print')
    def test_main_version(self, mock_print: mock.Mock) -> None:
        with self.assertRaises(SystemExit) as e:
            FlagParser.initialize(['--version'])
            mock_print.assert_called_with(__version__)
        self.assertEqual(e.exception.code, 0)

    @mock.patch('builtins.print')
    @mock.patch('proxy.common.flag.is_py2')
    def test_main_py2_exit(
            self,
            mock_is_py2: mock.Mock,
            mock_print: mock.Mock,
    ) -> None:
        mock_is_py2.return_value = True
        with self.assertRaises(SystemExit) as e:
            FlagParser.initialize()
        mock_print.assert_called_with(PY2_DEPRECATION_MESSAGE)
        self.assertEqual(e.exception.code, 1)
        mock_is_py2.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.common.flag.is_py2')
    def test_main_py3_runs(
            self,
            mock_is_py2: mock.Mock,
            mock_print: mock.Mock,
    ) -> None:
        mock_is_py2.return_value = False
        FlagParser.initialize()
        mock_is_py2.assert_called()
        mock_print.assert_not_called()


if __name__ == '__main__':
    unittest.main()
