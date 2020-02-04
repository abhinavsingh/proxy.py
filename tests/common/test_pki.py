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
import tempfile
import unittest
import subprocess
from unittest import mock
from typing import Tuple

from proxy.common import pki


class TestPki(unittest.TestCase):

    @mock.patch('subprocess.Popen')
    def test_run_openssl_command(self, mock_popen: mock.Mock) -> None:
        command = ['my', 'custom', 'command']
        mock_popen.return_value.returncode = 0
        self.assertTrue(pki.run_openssl_command(command, 10))
        mock_popen.assert_called_with(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

    def test_get_ext_config(self) -> None:
        self.assertEqual(pki.get_ext_config(None, None), b'')
        self.assertEqual(pki.get_ext_config([], None), b'')
        self.assertEqual(pki.get_ext_config(
            ['proxy.py'], None), b'[SAN]\nsubjectAltName=DNS:proxy.py')
        self.assertEqual(pki.get_ext_config(None, 'serverAuth'),
                         b'[PROXY]\nextendedKeyUsage=serverAuth')
        self.assertEqual(pki.get_ext_config(['proxy.py'], 'serverAuth'),
                         b'[SAN]\nsubjectAltName=DNS:proxy.py[PROXY]\nextendedKeyUsage=serverAuth')
        self.assertEqual(pki.get_ext_config(['proxy.py', 'www.proxy.py'], 'serverAuth'),
                         b'[SAN]\nsubjectAltName=DNS:proxy.py,DNS:www.proxy.py[PROXY]\nextendedKeyUsage=serverAuth')
        self.assertEqual(pki.get_ext_config(
            ['proxy.py']), b'[SAN]\nsubjectAltName=DNS:proxy.py')
        self.assertEqual(pki.get_ext_config(
            ['proxy.py']), b'[SAN]\nsubjectAltName=DNS:proxy.py')
        self.assertEqual(pki.get_ext_config(['proxy.py', 'www.proxy.py']),
                         b'[SAN]\nsubjectAltName=DNS:proxy.py,DNS:www.proxy.py')

    def test_ssl_config_no_ext(self) -> None:
        with pki.ssl_config() as (config_path, has_extension):
            self.assertFalse(has_extension)
            with open(config_path, 'rb') as config:
                self.assertEqual(config.read(), pki.DEFAULT_CONFIG)

    def test_ssl_config(self) -> None:
        with pki.ssl_config(['proxy.py']) as (config_path, has_extension):
            self.assertTrue(has_extension)
            with open(config_path, 'rb') as config:
                self.assertEqual(
                    config.read(),
                    pki.DEFAULT_CONFIG +
                    b'[SAN]\nsubjectAltName=DNS:proxy.py')

    def test_extfile_no_ext(self) -> None:
        with pki.ext_file() as config_path:
            with open(config_path, 'rb') as config:
                self.assertEqual(config.read(), b'')

    def test_extfile(self) -> None:
        with pki.ext_file(['proxy.py']) as config_path:
            with open(config_path, 'rb') as config:
                self.assertEqual(
                    config.read(),
                    b'[SAN]\nsubjectAltName=DNS:proxy.py')

    def test_gen_private_key(self) -> None:
        key_path, nopass_key_path = self._gen_private_key()
        self.assertTrue(os.path.exists(key_path))
        self.assertTrue(os.path.exists(nopass_key_path))
        os.remove(key_path)
        os.remove(nopass_key_path)

    def test_gen_public_key(self) -> None:
        key_path, nopass_key_path, crt_path = self._gen_public_private_key()
        self.assertTrue(os.path.exists(crt_path))
        # TODO: Assert generated public key matches private key
        os.remove(crt_path)
        os.remove(key_path)
        os.remove(nopass_key_path)

    def test_gen_csr(self) -> None:
        key_path, nopass_key_path, crt_path = self._gen_public_private_key()
        csr_path = os.path.join(tempfile.gettempdir(), 'test_gen_public.csr')
        pki.gen_csr(csr_path, nopass_key_path,
                    '/C=/ST=/L=/O=/OU=/CN=example.com')
        self.assertTrue(os.path.exists(csr_path))
        # TODO: Assert CSR is valid for provided crt and key
        os.remove(csr_path)
        os.remove(key_path)
        os.remove(nopass_key_path)

    def test_sign_csr(self) -> None:
        key_path, nopass_key_path, crt_path = self._gen_public_private_key()
        key_path, nopass_key_path_signed = self._gen_private_key()

        csr_path = os.path.join(tempfile.gettempdir(), 'test_gen_public.csr')
        pki.gen_csr(csr_path, nopass_key_path_signed,
                    '/C=/ST=/L=/O=/OU=/CN=example.com')

        csr_path_signed = os.path.join(tempfile.gettempdir(),
                                       'test_gen_public_signed.pem')
        pki.sign_csr(csr_path, csr_path_signed, nopass_key_path, crt_path,
                     str(123), ["example.com"])
        self.assertTrue(os.path.exists(csr_path_signed))
        os.remove(csr_path)
        os.remove(crt_path)
        os.remove(key_path)
        os.remove(nopass_key_path)
        os.remove(csr_path_signed)

    def test_gen_web_cert(self) -> None:
        key_path, nopass_key_path, crt_path = self._gen_public_private_key()
        key_path, nopass_key_path_signed = self._gen_private_key()

        out = os.path.join(tempfile.gettempdir(),
                           'web-csr.pem')
        pki.gen_crt(out, nopass_key_path_signed, nopass_key_path,
                    crt_path, "example.com", str(123))

        self.assertTrue(os.path.exists(out))

    def _gen_public_private_key(self) -> Tuple[str, str, str]:
        key_path, nopass_key_path = self._gen_private_key()
        crt_path = os.path.join(tempfile.gettempdir(), 'test_gen_public.crt')
        pki.gen_public_key(crt_path, nopass_key_path,
                           "password", '/CN=example.com')
        return (key_path, nopass_key_path, crt_path)

    def _gen_private_key(self) -> Tuple[str, str]:
        key_path = os.path.join(tempfile.gettempdir(), 'test_gen_private.key')
        nopass_key_path = os.path.join(
            tempfile.gettempdir(), 'test_gen_private_nopass.key')
        pki.gen_private_key(key_path, 'password')
        pki.remove_passphrase(key_path, 'password', nopass_key_path)
        return (key_path, nopass_key_path)
