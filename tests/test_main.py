# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
import logging
import tempfile
import os

from unittest import mock

from proxy.main import main
from proxy.common.utils import bytes_
from proxy.http.handler import ProtocolHandler

from proxy.common.constants import DEFAULT_LOG_LEVEL, DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_BASIC_AUTH
from proxy.common.constants import DEFAULT_TIMEOUT, DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HTTP_PROXY
from proxy.common.constants import DEFAULT_ENABLE_STATIC_SERVER, DEFAULT_ENABLE_EVENTS, DEFAULT_ENABLE_DEVTOOLS
from proxy.common.constants import DEFAULT_ENABLE_WEB_SERVER, DEFAULT_THREADLESS, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE
from proxy.common.constants import DEFAULT_CA_CERT_FILE, DEFAULT_CA_KEY_FILE, DEFAULT_CA_SIGNING_KEY_FILE
from proxy.common.constants import DEFAULT_PAC_FILE, DEFAULT_PLUGINS, DEFAULT_PID_FILE, DEFAULT_PORT
from proxy.common.constants import DEFAULT_NUM_WORKERS, DEFAULT_OPEN_FILE_LIMIT, DEFAULT_IPV6_HOSTNAME
from proxy.common.constants import DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_CLIENT_RECVBUF_SIZE
from proxy.common.constants import DEFAULT_EVENTS_QUEUE, COMMA
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
        mock_args.events_queue = DEFAULT_EVENTS_QUEUE

    @mock.patch('time.sleep')
    @mock.patch('proxy.main.load_plugins')
    @mock.patch('proxy.main.init_parser')
    @mock.patch('proxy.main.set_open_file_limit')
    @mock.patch('proxy.main.Flags')
    @mock.patch('proxy.main.AcceptorPool')
    @mock.patch('logging.basicConfig')
    def test_init_with_no_arguments(
            self,
            mock_logging_config: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_protocol_config: mock.Mock,
            mock_set_open_file_limit: mock.Mock,
            mock_init_parser: mock.Mock,
            mock_load_plugins: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()

        mock_args = mock_init_parser.return_value.parse_args.return_value
        self.mock_default_args(mock_args)
        main([])

        mock_init_parser.assert_called()
        mock_init_parser.return_value.parse_args.called_with([])

        mock_load_plugins.assert_called_with(b'proxy.http.proxy.HttpProxyPlugin,')
        mock_logging_config.assert_called_with(
            level=logging.INFO,
            format=DEFAULT_LOG_FORMAT
        )
        mock_set_open_file_limit.assert_called_with(mock_args.open_file_limit)
        mock_protocol_config.assert_called_with(
            auth_code=mock_args.basic_auth,
            backlog=mock_args.backlog,
            ca_cert_dir=mock_args.ca_cert_dir,
            ca_cert_file=mock_args.ca_cert_file,
            ca_key_file=mock_args.ca_key_file,
            ca_signing_key_file=mock_args.ca_signing_key_file,
            certfile=mock_args.cert_file,
            client_recvbuf_size=mock_args.client_recvbuf_size,
            hostname=mock_args.hostname,
            keyfile=mock_args.key_file,
            num_workers=0,
            pac_file=mock_args.pac_file,
            pac_file_url_path=mock_args.pac_file_url_path,
            port=mock_args.port,
            server_recvbuf_size=mock_args.server_recvbuf_size,
            disable_headers=[
                header.lower() for header in bytes_(
                    mock_args.disable_headers).split(COMMA) if header.strip() != b''],
            static_server_dir=mock_args.static_server_dir,
            enable_static_server=mock_args.enable_static_server,
            devtools_event_queue=None,
            devtools_ws_path=DEFAULT_DEVTOOLS_WS_PATH,
            timeout=DEFAULT_TIMEOUT,
            threadless=DEFAULT_THREADLESS,
            enable_events=DEFAULT_ENABLE_EVENTS,
            events_queue=DEFAULT_EVENTS_QUEUE,
        )
        mock_acceptor_pool.assert_called_with(
            flags=mock_protocol_config.return_value,
            work_klass=ProtocolHandler,
        )
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_acceptor_pool.return_value.shutdown.assert_called()
        mock_sleep.assert_called_with(1)

    @mock.patch('time.sleep')
    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.main.init_parser')
    @mock.patch('proxy.main.AcceptorPool')
    def test_pid_file_is_written_and_removed(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_init_parser: mock.Mock,
            mock_open: mock.Mock,
            mock_exists: mock.Mock,
            mock_remove: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        pid_file = get_temp_file('pid')
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_init_parser.return_value.parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.pid_file = pid_file
        main(['--pid-file', pid_file])
        mock_init_parser.assert_called()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            bytes_(os.getpid()))
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('time.sleep')
    @mock.patch('proxy.main.Flags')
    @mock.patch('proxy.main.AcceptorPool')
    def test_basic_auth(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_protocol_config: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        main(['--basic-auth', 'user:pass'])
        flags = mock_protocol_config.return_value
        mock_acceptor_pool.assert_called_with(
            flags=flags,
            work_klass=ProtocolHandler)
        self.assertEqual(mock_protocol_config.call_args[1]['auth_code'], b'Basic dXNlcjpwYXNz')

    @mock.patch('builtins.print')
    def test_main_version(
            self,
            mock_print: mock.Mock) -> None:
        with self.assertRaises(SystemExit):
            main(['--version'])
            mock_print.assert_called_with(__version__)

    @mock.patch('time.sleep')
    @mock.patch('builtins.print')
    @mock.patch('proxy.main.AcceptorPool')
    @mock.patch('proxy.main.is_py3')
    def test_main_py3_runs(
            self,
            mock_is_py3: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_print: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_is_py3.return_value = True
        main([])
        mock_is_py3.assert_called()
        mock_print.assert_not_called()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.main.is_py3')
    def test_main_py2_exit(
            self,
            mock_is_py3: mock.Mock,
            mock_print: mock.Mock) -> None:
        mock_is_py3.return_value = False
        with self.assertRaises(SystemExit) as e:
            main([])
        mock_print.assert_called_with(
            'DEPRECATION: "develop" branch no longer supports Python 2.7.  Kindly upgrade to Python 3+. '
            'If for some reasons you cannot upgrade, consider using "master" branch or simply '
            '"pip install proxy.py==0.3".'
            '\n\n'
            'DEPRECATION: Python 2.7 will reach the end of its life on January 1st, 2020. '
            'Please upgrade your Python as Python 2.7 won\'t be maintained after that date. '
            'A future version of pip will drop support for Python 2.7.'
        )
        self.assertEqual(e.exception.code, 1)
        mock_is_py3.assert_called()
