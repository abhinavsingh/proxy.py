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
import logging
import tempfile
import os

from unittest import mock
from typing import List

from proxy.proxy import main, Proxy
from proxy.common.utils import bytes_
from proxy.http.handler import HttpProtocolHandler

from proxy.common.constants import DEFAULT_LOG_LEVEL, DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_BASIC_AUTH
from proxy.common.constants import DEFAULT_TIMEOUT, DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HTTP_PROXY
from proxy.common.constants import DEFAULT_ENABLE_STATIC_SERVER, DEFAULT_ENABLE_EVENTS, DEFAULT_ENABLE_DEVTOOLS
from proxy.common.constants import DEFAULT_ENABLE_WEB_SERVER, DEFAULT_THREADLESS, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE
from proxy.common.constants import DEFAULT_CA_CERT_FILE, DEFAULT_CA_KEY_FILE, DEFAULT_CA_SIGNING_KEY_FILE
from proxy.common.constants import DEFAULT_PAC_FILE, DEFAULT_PLUGINS, DEFAULT_PID_FILE, DEFAULT_PORT
from proxy.common.constants import DEFAULT_NUM_WORKERS, DEFAULT_OPEN_FILE_LIMIT, DEFAULT_IPV6_HOSTNAME
from proxy.common.constants import DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_CLIENT_RECVBUF_SIZE, PY2_DEPRECATION_MESSAGE
from proxy.common.version import __version__


def get_temp_file(name: str) -> str:
    return os.path.join(tempfile.gettempdir(), name)


class TestMain(unittest.TestCase):

    @staticmethod
    def mock_default_args(mock_args: mock.Mock) -> None:
        mock_args.version = False
        mock_args.cert_file = DEFAULT_CERT_FILE
        mock_args.key_file = DEFAULT_KEY_FILE
        mock_args.ca_key_file = DEFAULT_CA_KEY_FILE
        mock_args.ca_cert_file = DEFAULT_CA_CERT_FILE
        mock_args.ca_signing_key_file = DEFAULT_CA_SIGNING_KEY_FILE
        mock_args.pid_file = DEFAULT_PID_FILE
        mock_args.log_file = DEFAULT_LOG_FILE
        mock_args.log_level = DEFAULT_LOG_LEVEL
        mock_args.log_format = DEFAULT_LOG_FORMAT
        mock_args.basic_auth = DEFAULT_BASIC_AUTH
        mock_args.hostname = DEFAULT_IPV6_HOSTNAME
        mock_args.port = DEFAULT_PORT
        mock_args.num_workers = DEFAULT_NUM_WORKERS
        mock_args.disable_http_proxy = DEFAULT_DISABLE_HTTP_PROXY
        mock_args.enable_web_server = DEFAULT_ENABLE_WEB_SERVER
        mock_args.pac_file = DEFAULT_PAC_FILE
        mock_args.plugins = DEFAULT_PLUGINS
        mock_args.server_recvbuf_size = DEFAULT_SERVER_RECVBUF_SIZE
        mock_args.client_recvbuf_size = DEFAULT_CLIENT_RECVBUF_SIZE
        mock_args.open_file_limit = DEFAULT_OPEN_FILE_LIMIT
        mock_args.enable_static_server = DEFAULT_ENABLE_STATIC_SERVER
        mock_args.enable_devtools = DEFAULT_ENABLE_DEVTOOLS
        mock_args.devtools_event_queue = None
        mock_args.devtools_ws_path = DEFAULT_DEVTOOLS_WS_PATH
        mock_args.timeout = DEFAULT_TIMEOUT
        mock_args.threadless = DEFAULT_THREADLESS
        mock_args.enable_events = DEFAULT_ENABLE_EVENTS

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.Flags')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('logging.basicConfig')
    def test_init_with_no_arguments(
            self,
            mock_logging_config: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_flags: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()

        input_args: List[str] = []
        main(input_args)

        mock_logging_config.assert_called_with(
            level=logging.INFO,
            format=DEFAULT_LOG_FORMAT
        )
        mock_acceptor_pool.assert_called_with(
            flags=mock_flags.return_value,
            work_klass=HttpProtocolHandler,
        )
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_acceptor_pool.return_value.shutdown.assert_called()
        mock_sleep.assert_called()

    @mock.patch('time.sleep')
    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.common.flag.FlagParser.parse_args')
    def test_pid_file_is_written_and_removed(
            self,
            mock_parse_args: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_open: mock.Mock,
            mock_exists: mock.Mock,
            mock_remove: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        pid_file = get_temp_file('pid')
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.pid_file = pid_file
        main(['--pid-file', pid_file])
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            bytes_(os.getpid()))
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.AcceptorPool')
    def test_basic_auth(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()

        input_args = ['--basic-auth', 'user:pass']
        flgs = Proxy.initialize(input_args)

        main(input_args=input_args)
        mock_acceptor_pool.assert_called_once()
        self.assertEqual(
            flgs.auth_code,
            b'Basic dXNlcjpwYXNz')

    @mock.patch('time.sleep')
    @mock.patch('builtins.print')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.proxy.Proxy.is_py3')
    def test_main_py3_runs(
            self,
            mock_is_py3: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_print: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()

        input_args = ['--basic-auth', 'user:pass']
        mock_is_py3.return_value = True

        main(input_args, num_workers=1)

        mock_is_py3.assert_called()
        mock_print.assert_not_called()
        mock_acceptor_pool.assert_called_once()
        mock_acceptor_pool.return_value.setup.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.proxy.Proxy.is_py3')
    def test_main_py2_exit(
            self,
            mock_is_py3: mock.Mock,
            mock_print: mock.Mock) -> None:
        mock_is_py3.return_value = False
        with self.assertRaises(SystemExit) as e:
            main(num_workers=1)
        mock_print.assert_called_with(PY2_DEPRECATION_MESSAGE)
        self.assertEqual(e.exception.code, 1)
        mock_is_py3.assert_called()

    @mock.patch('builtins.print')
    def test_main_version(
            self,
            mock_print: mock.Mock) -> None:
        with self.assertRaises(SystemExit) as e:
            main(['--version'])
            mock_print.assert_called_with(__version__)
        self.assertEqual(e.exception.code, 0)
