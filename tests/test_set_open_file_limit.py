# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import unittest
from unittest import mock

from proxy.proxy import Proxy

if os.name != 'nt':
    import resource


@unittest.skipIf(
    os.name == 'nt',
    'Open file limit tests disabled for Windows',
)
class TestSetOpenFileLimit(unittest.TestCase):

    @mock.patch('resource.getrlimit', return_value=(128, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock,
    ) -> None:
        Proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_called_with(resource.RLIMIT_NOFILE, (256, 1024))

    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock,
    ) -> None:
        Proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()

    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called_coz_upper_bound_check(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock,
    ) -> None:
        Proxy.set_open_file_limit(1024)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()
