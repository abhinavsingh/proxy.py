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
import tempfile
import os

from unittest import mock

from proxy.proxy import main, entry_point
from proxy.common.utils import bytes_
from proxy.http.handler import HttpProtocolHandler
from proxy.common.flag import FlagParser

from proxy.common.constants import DEFAULT_ENABLE_DASHBOARD, DEFAULT_LOG_LEVEL, DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT
from proxy.common.constants import DEFAULT_TIMEOUT, DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HTTP_PROXY
from proxy.common.constants import DEFAULT_ENABLE_STATIC_SERVER, DEFAULT_ENABLE_EVENTS, DEFAULT_ENABLE_DEVTOOLS
from proxy.common.constants import DEFAULT_ENABLE_WEB_SERVER, DEFAULT_THREADLESS, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE
from proxy.common.constants import DEFAULT_CA_CERT_FILE, DEFAULT_CA_KEY_FILE, DEFAULT_CA_SIGNING_KEY_FILE
from proxy.common.constants import DEFAULT_PAC_FILE, DEFAULT_PLUGINS, DEFAULT_PID_FILE, DEFAULT_PORT, DEFAULT_BASIC_AUTH
from proxy.common.constants import DEFAULT_NUM_WORKERS, DEFAULT_OPEN_FILE_LIMIT, DEFAULT_IPV6_HOSTNAME
from proxy.common.constants import DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_CLIENT_RECVBUF_SIZE, PY2_DEPRECATION_MESSAGE
from proxy.common.constants import PLUGIN_INSPECT_TRAFFIC, PLUGIN_DASHBOARD, PLUGIN_DEVTOOLS_PROTOCOL, PLUGIN_WEB_SERVER
from proxy.common.constants import PLUGIN_HTTP_PROXY
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
        mock_args.pac_file = DEFAULT_PAC_FILE
        mock_args.plugins = DEFAULT_PLUGINS
        mock_args.server_recvbuf_size = DEFAULT_SERVER_RECVBUF_SIZE
        mock_args.client_recvbuf_size = DEFAULT_CLIENT_RECVBUF_SIZE
        mock_args.open_file_limit = DEFAULT_OPEN_FILE_LIMIT
        mock_args.devtools_event_queue = None
        mock_args.devtools_ws_path = DEFAULT_DEVTOOLS_WS_PATH
        mock_args.timeout = DEFAULT_TIMEOUT
        mock_args.threadless = DEFAULT_THREADLESS
        mock_args.enable_web_server = DEFAULT_ENABLE_WEB_SERVER
        mock_args.enable_static_server = DEFAULT_ENABLE_STATIC_SERVER
        mock_args.enable_devtools = DEFAULT_ENABLE_DEVTOOLS
        mock_args.enable_events = DEFAULT_ENABLE_EVENTS
        mock_args.enable_dashboard = DEFAULT_ENABLE_DASHBOARD

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.FlagParser.initialize')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    def test_entry_point(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_initialize: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_initialize.return_value.enable_events = False
        entry_point()
        mock_event_manager.assert_not_called()
        mock_acceptor_pool.assert_called_with(
            flags=mock_initialize.return_value,
            work_klass=HttpProtocolHandler,
            event_queue=None,
        )
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_acceptor_pool.return_value.shutdown.assert_called()
        mock_sleep.assert_called()

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.FlagParser.initialize')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    def test_main_with_no_arguments(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_initialize: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_initialize.return_value.enable_events = False
        main([])
        mock_event_manager.assert_not_called()
        mock_acceptor_pool.assert_called_with(
            flags=mock_initialize.return_value,
            work_klass=HttpProtocolHandler,
            event_queue=None,
        )
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_acceptor_pool.return_value.shutdown.assert_called()
        mock_sleep.assert_called()

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.FlagParser.initialize')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    def test_enable_events(
        self,
        mock_acceptor_pool: mock.Mock,
        mock_event_manager: mock.Mock,
        mock_initialize: mock.Mock,
        mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_initialize.return_value.enable_events = True
        main([])
        mock_event_manager.assert_called_once()
        mock_event_manager.return_value.start_event_dispatcher.assert_called_once()
        mock_event_manager.return_value.stop_event_dispatcher.assert_called_once()
        mock_acceptor_pool.assert_called_with(
            flags=mock_initialize.return_value,
            work_klass=HttpProtocolHandler,
            event_queue=mock_event_manager.return_value.event_queue,
        )
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_acceptor_pool.return_value.shutdown.assert_called()
        mock_sleep.assert_called()

    @mock.patch('time.sleep')
    @mock.patch('proxy.common.plugins.Plugins.load')
    @mock.patch('proxy.common.flag.FlagParser.parse_args')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    def test_enable_dashboard(
        self,
        mock_acceptor_pool: mock.Mock,
        mock_event_manager: mock.Mock,
        mock_parse_args: mock.Mock,
        mock_load_plugins: mock.Mock,
        mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.enable_dashboard = True
        main(['--enable-dashboard'])
        mock_load_plugins.assert_called()
        self.assertEqual(
            mock_load_plugins.call_args_list[0][0][0], [
                bytes_(PLUGIN_WEB_SERVER),
                bytes_(PLUGIN_DASHBOARD),
                bytes_(PLUGIN_INSPECT_TRAFFIC),
                bytes_(PLUGIN_DEVTOOLS_PROTOCOL),
                bytes_(PLUGIN_HTTP_PROXY),
            ],
        )
        mock_parse_args.assert_called_once()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()
        # dashboard will also enable eventing
        mock_event_manager.assert_called_once()
        mock_event_manager.return_value.start_event_dispatcher.assert_called_once()
        mock_event_manager.return_value.stop_event_dispatcher.assert_called_once()

    @mock.patch('time.sleep')
    @mock.patch('proxy.common.plugins.Plugins.load')
    @mock.patch('proxy.common.flag.FlagParser.parse_args')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    def test_enable_devtools(
        self,
        mock_acceptor_pool: mock.Mock,
        mock_event_manager: mock.Mock,
        mock_parse_args: mock.Mock,
        mock_load_plugins: mock.Mock,
        mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.enable_devtools = True
        main(['--enable-devtools'])
        mock_load_plugins.assert_called()
        self.assertEqual(
            mock_load_plugins.call_args_list[0][0][0], [
                bytes_(PLUGIN_DEVTOOLS_PROTOCOL),
                bytes_(PLUGIN_WEB_SERVER),
                bytes_(PLUGIN_HTTP_PROXY),
            ],
        )
        mock_parse_args.assert_called_once()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()
        # Currently --enable-devtools alone doesn't enable eventing core
        mock_event_manager.assert_not_called()

    @mock.patch('time.sleep')
    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.common.flag.FlagParser.parse_args')
    def test_pid_file_is_written_and_removed(
            self,
            mock_parse_args: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_open: mock.Mock,
            mock_exists: mock.Mock,
            mock_remove: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        pid_file = get_temp_file('pid')
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.pid_file = pid_file
        main(['--pid-file', pid_file])
        mock_parse_args.assert_called_once()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_event_manager.assert_not_called()
        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            bytes_(os.getpid()),
        )
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    def test_basic_auth_flag_is_base64_encoded(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()

        input_args = ['--basic-auth', 'user:pass']
        flgs = FlagParser.initialize(input_args)

        main(input_args=input_args)
        mock_event_manager.assert_not_called()
        mock_acceptor_pool.assert_called_once()
        self.assertEqual(
            flgs.auth_code,
            b'dXNlcjpwYXNz',
        )

    @mock.patch('time.sleep')
    @mock.patch('builtins.print')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.common.flag.is_py2')
    def test_main_py3_runs(
            self,
            mock_is_py2: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_print: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()

        input_args = ['--basic-auth', 'user:pass']
        mock_is_py2.return_value = False

        main(input_args, num_workers=1)

        mock_is_py2.assert_called()
        mock_print.assert_not_called()

        mock_event_manager.assert_not_called()
        mock_acceptor_pool.assert_called_once()
        mock_acceptor_pool.return_value.setup.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.common.flag.is_py2')
    def test_main_py2_exit(
            self,
            mock_is_py2: mock.Mock,
            mock_print: mock.Mock,
    ) -> None:
        mock_is_py2.return_value = True
        with self.assertRaises(SystemExit) as e:
            main(num_workers=1)
        mock_print.assert_called_with(PY2_DEPRECATION_MESSAGE)
        self.assertEqual(e.exception.code, 1)
        mock_is_py2.assert_called()

    @mock.patch('builtins.print')
    def test_main_version(
            self,
            mock_print: mock.Mock,
    ) -> None:
        with self.assertRaises(SystemExit) as e:
            main(['--version'])
            mock_print.assert_called_with(__version__)
        self.assertEqual(e.exception.code, 0)

    # def test_pac_file(self) -> None:
    #     pass

    # def test_imports_plugin(self) -> None:
    #     pass

    # def test_cannot_enable_https_proxy_and_tls_interception_mutually(self) -> None:
    #     pass
