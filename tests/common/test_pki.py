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
import subprocess
from unittest import mock

from proxy.common import pki


class TestPki(unittest.TestCase):

    @mock.patch('subprocess.Popen')
    def test_run_openssl_command(self, mock_popen: mock.Mock) -> None:
        command = ['my', 'custom', 'command']
        mock_popen.return_value.returncode = 0
        self.assertTrue(pki.run_openssl_command(command, 10))
        mock_popen.assert_called_with(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_get_ext_config(self) -> None:
        self.assertEqual(pki.get_ext_config(None, None), b'')
        self.assertEqual(pki.get_ext_config([], None), b'')
        self.assertEqual(pki.get_ext_config(['proxy.py'], None), b'\nsubjectAltName=DNS:proxy.py')
        self.assertEqual(pki.get_ext_config(None, 'serverAuth'), b'\nextendedKeyUsage=serverAuth')
        self.assertEqual(pki.get_ext_config(['proxy.py'], 'serverAuth'),
                         b'\nsubjectAltName=DNS:proxy.py\nextendedKeyUsage=serverAuth')
        self.assertEqual(pki.get_ext_config(['proxy.py', 'www.proxy.py'], 'serverAuth'),
                         b'\nsubjectAltName=DNS:proxy.py,DNS:www.proxy.py\nextendedKeyUsage=serverAuth')

    def test_ssl_config_no_ext(self) -> None:
        with pki.ssl_config() as (config_path, has_extension):
            self.assertFalse(has_extension)
            with open(config_path, 'rb') as config:
                self.assertEqual(config.read(), pki.DEFAULT_CONFIG)

    def test_ssl_config(self) -> None:
        with pki.ssl_config(['proxy.py']) as (config_path, has_extension):
            self.assertTrue(has_extension)
            with open(config_path, 'rb') as config:
                self.assertEqual(config.read(), pki.DEFAULT_CONFIG + b'\n[PROXY]\nsubjectAltName=DNS:proxy.py')

    def test_extfile_no_ext(self) -> None:
        with pki.ext_file() as config_path:
            with open(config_path, 'rb') as config:
                self.assertEqual(config.read(), b'')

    def test_extfile(self) -> None:
        with pki.ext_file(['proxy.py']) as config_path:
            with open(config_path, 'rb') as config:
                self.assertEqual(config.read(), b'\nsubjectAltName=DNS:proxy.py')

    def test_gen_private_key(self) -> None:
        pass

    def test_gen_public_key(self) -> None:
        pass

    def test_gen_csr(self) -> None:
        pass

    def test_sign_csr(self) -> None:
        pass
