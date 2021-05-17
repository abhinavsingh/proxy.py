# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from concurrent.futures import ProcessPoolExecutor
from proxy.common.utils import bytes_
from proxy.common.constants import PLUGIN_HTTP_PROXY
import unittest

from typing import List, Dict

from proxy.proxy import Proxy
from proxy.http.proxy import HttpProxyPlugin
from proxy.plugin import CacheResponsesPlugin
from proxy.plugin import FilterByUpstreamHostPlugin


def clean_Proxy_initialize(*args, **kwargs):
    with ProcessPoolExecutor() as pool:
        return pool.submit(Proxy.initialize, *args, **kwargs).result()


class TestFlags(unittest.TestCase):
    def assert_plugins(self, expected: Dict[str, List[type]]) -> None:
        for k in expected:
            self.assertIn(k.encode(), self.flags.plugins)
            for p in expected[k]:
                self.assertIn(p, self.flags.plugins[k.encode()])
                self.assertEqual(
                    len([o for o in self.flags.plugins[k.encode()] if o == p]), 1)

    def assert_plugin_flags(self, *flags: str) -> None:
        non_plugin_flags = set(dict(clean_Proxy_initialize()._get_kwargs()))
        plugin_flags = set(dict(self.flags._get_kwargs())) - non_plugin_flags
        for flag in flags:
            self.assertIn(flag.lstrip('-').replace('-', '_'), plugin_flags,
                          "Can't find '%s' flag" % flag)

    def test_load_plugin_from_bytes(self) -> None:
        self.flags = Proxy.initialize([], plugins=[
            b'proxy.plugin.CacheResponsesPlugin',
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [CacheResponsesPlugin]})

    def test_load_plugins_from_bytes(self) -> None:
        self.flags = Proxy.initialize([], plugins=[
            b'proxy.plugin.CacheResponsesPlugin',
            b'proxy.plugin.FilterByUpstreamHostPlugin',
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [
            CacheResponsesPlugin,
            FilterByUpstreamHostPlugin,
        ]})

    def test_load_plugin_from_args(self) -> None:
        self.flags = Proxy.initialize([
            '--plugins', 'proxy.plugin.CacheResponsesPlugin',
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [CacheResponsesPlugin]})

    def test_load_plugins_from_args(self) -> None:
        self.flags = Proxy.initialize([
            '--plugins', 'proxy.plugin.CacheResponsesPlugin,proxy.plugin.FilterByUpstreamHostPlugin',
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [
            CacheResponsesPlugin,
            FilterByUpstreamHostPlugin,
        ]})

    def test_load_plugin_from_class(self) -> None:
        self.flags = Proxy.initialize([], plugins=[
            CacheResponsesPlugin,
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [CacheResponsesPlugin]})

    def test_load_plugins_from_class(self) -> None:
        self.flags = Proxy.initialize([], plugins=[
            CacheResponsesPlugin,
            FilterByUpstreamHostPlugin,
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [
            CacheResponsesPlugin,
            FilterByUpstreamHostPlugin,
        ]})

    def test_load_plugins_from_bytes_and_class(self) -> None:
        self.flags = Proxy.initialize([], plugins=[
            CacheResponsesPlugin,
            b'proxy.plugin.FilterByUpstreamHostPlugin',
        ])
        self.assert_plugins({'HttpProxyBasePlugin': [
            CacheResponsesPlugin,
            FilterByUpstreamHostPlugin,
        ]})

    def test_unique_plugin_from_bytes(self) -> None:
        self.flags = Proxy.initialize([], plugins=[
            bytes_(PLUGIN_HTTP_PROXY),
        ])
        self.assert_plugins({'HttpProtocolHandlerPlugin': [
            HttpProxyPlugin,
        ]})

    def test_unique_plugin_from_args(self) -> None:
        self.flags = Proxy.initialize([
            '--plugins', PLUGIN_HTTP_PROXY,
        ])
        self.assert_plugins({'HttpProtocolHandlerPlugin': [
            HttpProxyPlugin,
        ]})

    def test_unique_plugin_from_class(self) -> None:
        self.flags = Proxy.initialize([], plugins=[
            HttpProxyPlugin,
        ])
        self.assert_plugins({'HttpProtocolHandlerPlugin': [
            HttpProxyPlugin,
        ]})

    def test_plugin_flags_with_plugin(self) -> None:
        self.flags = clean_Proxy_initialize([
            '--plugin', 'tests.plugin.dummy.DummyPlugin'])
        self.assert_plugin_flags('--dummy-1', '--dummy-2')

    def test_plugin_flags_with_plugins(self) -> None:
        self.flags = clean_Proxy_initialize([
            '--plugins', 'tests.plugin.dummy.DummyPlugin'])
        self.assert_plugin_flags('--dummy-1', '--dummy-2')


if __name__ == '__main__':
    unittest.main()
