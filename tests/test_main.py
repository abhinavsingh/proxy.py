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
from unittest import mock

from proxy.proxy import main, entry_point
from proxy.common.utils import bytes_
from proxy.common.constants import (  # noqa: WPS450
    DEFAULT_ENABLE_REVERSE_PROXY, DEFAULT_PORT, DEFAULT_PLUGINS, DEFAULT_TIMEOUT, DEFAULT_KEY_FILE,
    DEFAULT_LOG_FILE, DEFAULT_PAC_FILE, DEFAULT_PID_FILE, PLUGIN_DASHBOARD,
    DEFAULT_CERT_FILE, DEFAULT_LOG_LEVEL, DEFAULT_PORT_FILE, PLUGIN_HTTP_PROXY,
    PLUGIN_PROXY_AUTH, PLUGIN_WEB_SERVER, DEFAULT_BASIC_AUTH,
    DEFAULT_LOG_FORMAT, DEFAULT_THREADLESS, DEFAULT_WORK_KLASS,
    DEFAULT_CA_CERT_DIR, DEFAULT_CA_KEY_FILE, DEFAULT_NUM_WORKERS,
    DEFAULT_CA_CERT_FILE, DEFAULT_ENABLE_EVENTS, DEFAULT_IPV6_HOSTNAME,
    DEFAULT_NUM_ACCEPTORS, DEFAULT_LOCAL_EXECUTOR, PLUGIN_INSPECT_TRAFFIC,
    DEFAULT_ENABLE_DEVTOOLS, DEFAULT_OPEN_FILE_LIMIT, DEFAULT_DEVTOOLS_WS_PATH,
    DEFAULT_ENABLE_DASHBOARD, PLUGIN_DEVTOOLS_PROTOCOL,
    DEFAULT_ENABLE_SSH_TUNNEL, DEFAULT_ENABLE_WEB_SERVER,
    DEFAULT_DISABLE_HTTP_PROXY, PLUGIN_WEBSOCKET_TRANSPORT,
    DEFAULT_CA_SIGNING_KEY_FILE, DEFAULT_CLIENT_RECVBUF_SIZE,
    DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_ENABLE_STATIC_SERVER,
    _env_threadless_compliant,
)


class TestMain(unittest.TestCase):

    @staticmethod
    def mock_default_args(mock_args: mock.Mock) -> None:
        """Use when trying to mock parse_args"""
        mock_args.version = False
        mock_args.cert_file = DEFAULT_CERT_FILE
        mock_args.key_file = DEFAULT_KEY_FILE
        mock_args.ca_key_file = DEFAULT_CA_KEY_FILE
        mock_args.ca_cert_file = DEFAULT_CA_CERT_FILE
        mock_args.ca_signing_key_file = DEFAULT_CA_SIGNING_KEY_FILE
        mock_args.ca_cert_dir = DEFAULT_CA_CERT_DIR
        mock_args.pid_file = DEFAULT_PID_FILE
        mock_args.log_file = DEFAULT_LOG_FILE
        mock_args.log_level = DEFAULT_LOG_LEVEL
        mock_args.log_format = DEFAULT_LOG_FORMAT
        mock_args.basic_auth = DEFAULT_BASIC_AUTH
        mock_args.hostname = DEFAULT_IPV6_HOSTNAME
        mock_args.port = DEFAULT_PORT
        mock_args.num_acceptors = DEFAULT_NUM_ACCEPTORS
        mock_args.num_workers = DEFAULT_NUM_WORKERS
        mock_args.disable_http_proxy = DEFAULT_DISABLE_HTTP_PROXY
        mock_args.pac_file = DEFAULT_PAC_FILE
        mock_args.plugins = DEFAULT_PLUGINS
        mock_args.auth_plugin = PLUGIN_PROXY_AUTH
        mock_args.server_recvbuf_size = DEFAULT_SERVER_RECVBUF_SIZE
        mock_args.client_recvbuf_size = DEFAULT_CLIENT_RECVBUF_SIZE
        mock_args.open_file_limit = DEFAULT_OPEN_FILE_LIMIT
        mock_args.devtools_event_queue = None
        mock_args.devtools_ws_path = DEFAULT_DEVTOOLS_WS_PATH
        mock_args.timeout = DEFAULT_TIMEOUT
        mock_args.threadless = DEFAULT_THREADLESS
        mock_args.threaded = not DEFAULT_THREADLESS
        mock_args.enable_web_server = DEFAULT_ENABLE_WEB_SERVER
        mock_args.enable_static_server = DEFAULT_ENABLE_STATIC_SERVER
        mock_args.enable_devtools = DEFAULT_ENABLE_DEVTOOLS
        mock_args.enable_events = DEFAULT_ENABLE_EVENTS
        mock_args.enable_dashboard = DEFAULT_ENABLE_DASHBOARD
        mock_args.work_klass = DEFAULT_WORK_KLASS
        mock_args.local_executor = int(DEFAULT_LOCAL_EXECUTOR)
        mock_args.port_file = DEFAULT_PORT_FILE
        mock_args.enable_ssh_tunnel = DEFAULT_ENABLE_SSH_TUNNEL
        mock_args.enable_reverse_proxy = DEFAULT_ENABLE_REVERSE_PROXY

    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.FlagParser.initialize')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.proxy.ThreadlessPool')
    @mock.patch('proxy.proxy.Listener')
    def test_entry_point(
            self,
            mock_listener: mock.Mock,
            mock_executor_pool: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_initialize: mock.Mock,
            mock_sleep: mock.Mock,
            mock_open: mock.Mock,
            mock_exists: mock.Mock,
            mock_remove: mock.Mock,
    ) -> None:
        pid_file = os.path.join(tempfile.gettempdir(), 'pid')
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_initialize.return_value.local_executor = 0
        mock_initialize.return_value.enable_events = False
        mock_initialize.return_value.pid_file = pid_file
        mock_initialize.return_value.port_file = None
        mock_initialize.return_value.enable_ssh_tunnel = False
        entry_point()
        mock_event_manager.assert_not_called()
        mock_listener.assert_called_once_with(
            flags=mock_initialize.return_value,
        )
        mock_executor_pool.assert_called_once_with(
            flags=mock_initialize.return_value,
            event_queue=None,
        )
        mock_acceptor_pool.assert_called_once_with(
            flags=mock_initialize.return_value,
            listener=mock_listener.return_value,
            executor_queues=mock_executor_pool.return_value.work_queues,
            executor_pids=mock_executor_pool.return_value.work_pids,
            executor_locks=mock_executor_pool.return_value.work_locks,
            event_queue=None,
        )
        mock_acceptor_pool.return_value.setup.assert_called_once()
        mock_acceptor_pool.return_value.shutdown.assert_called_once()
        mock_listener.return_value.shutdown.assert_called_once()
        mock_sleep.assert_called()

        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            bytes_(os.getpid()),
        )
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.FlagParser.initialize')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.proxy.ThreadlessPool')
    @mock.patch('proxy.proxy.Listener')
    def test_main_with_no_flags(
            self,
            mock_listener: mock.Mock,
            mock_executor_pool: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_initialize: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_initialize.return_value.local_executor = 0
        mock_initialize.return_value.enable_events = False
        mock_initialize.return_value.port_file = None
        mock_initialize.return_value.enable_ssh_tunnel = False
        main()
        mock_event_manager.assert_not_called()
        mock_listener.assert_called_once_with(
            flags=mock_initialize.return_value,
        )
        mock_executor_pool.assert_called_once_with(
            flags=mock_initialize.return_value,
            event_queue=None,
        )
        mock_acceptor_pool.assert_called_once_with(
            flags=mock_initialize.return_value,
            listener=mock_listener.return_value,
            executor_queues=mock_executor_pool.return_value.work_queues,
            executor_pids=mock_executor_pool.return_value.work_pids,
            executor_locks=mock_executor_pool.return_value.work_locks,
            event_queue=None,
        )
        mock_acceptor_pool.return_value.setup.assert_called_once()
        mock_acceptor_pool.return_value.shutdown.assert_called_once()
        mock_listener.return_value.shutdown.assert_called_once()
        mock_sleep.assert_called()

    @mock.patch('time.sleep')
    @mock.patch('proxy.proxy.FlagParser.initialize')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.proxy.ThreadlessPool')
    @mock.patch('proxy.proxy.Listener')
    def test_enable_events(
            self,
            mock_listener: mock.Mock,
            mock_executor_pool: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_initialize: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_initialize.return_value.local_executor = 0
        mock_initialize.return_value.enable_events = True
        mock_initialize.return_value.port_file = None
        mock_initialize.return_value.enable_ssh_tunnel = False
        main()
        mock_event_manager.assert_called_once()
        mock_event_manager.return_value.setup.assert_called_once()
        mock_event_manager.return_value.shutdown.assert_called_once()
        mock_listener.assert_called_once_with(
            flags=mock_initialize.return_value,
        )
        mock_executor_pool.assert_called_once_with(
            flags=mock_initialize.return_value,
            event_queue=mock_event_manager.return_value.queue,
        )
        mock_acceptor_pool.assert_called_once_with(
            flags=mock_initialize.return_value,
            listener=mock_listener.return_value,
            event_queue=mock_event_manager.return_value.queue,
            executor_queues=mock_executor_pool.return_value.work_queues,
            executor_pids=mock_executor_pool.return_value.work_pids,
            executor_locks=mock_executor_pool.return_value.work_locks,
        )
        mock_acceptor_pool.return_value.setup.assert_called_once()
        mock_acceptor_pool.return_value.shutdown.assert_called_once()
        mock_listener.return_value.shutdown.assert_called_once()
        mock_sleep.assert_called()

    @mock.patch('time.sleep')
    @mock.patch('proxy.common.plugins.Plugins.load')
    @mock.patch('proxy.common.flag.FlagParser.parse_args')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.proxy.ThreadlessPool')
    @mock.patch('proxy.proxy.Listener')
    def test_enable_dashboard(
            self,
            mock_listener: mock.Mock,
            mock_executor_pool: mock.Mock,
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
        mock_args.local_executor = 0
        main()
        mock_load_plugins.assert_called()
        self.assertEqual(
            mock_load_plugins.call_args_list[0][0][0], [
                bytes_(PLUGIN_WEB_SERVER),
                bytes_(PLUGIN_DASHBOARD),
                bytes_(PLUGIN_WEBSOCKET_TRANSPORT),
                bytes_(PLUGIN_INSPECT_TRAFFIC),
                bytes_(PLUGIN_DEVTOOLS_PROTOCOL),
                bytes_(PLUGIN_HTTP_PROXY),
            ],
        )
        # TODO: Assert arguments passed to parse_arg
        mock_parse_args.assert_called_once()
        # dashboard will also enable eventing
        mock_event_manager.assert_called_once()
        mock_event_manager.return_value.setup.assert_called_once()
        mock_event_manager.return_value.shutdown.assert_called_once()
        if _env_threadless_compliant():
            mock_executor_pool.assert_called_once()
            mock_executor_pool.return_value.setup.assert_called_once()
        mock_acceptor_pool.assert_called_once()
        mock_acceptor_pool.return_value.setup.assert_called_once()
        mock_listener.return_value.setup.assert_called_once()

    @mock.patch('time.sleep')
    @mock.patch('proxy.common.plugins.Plugins.load')
    @mock.patch('proxy.common.flag.FlagParser.parse_args')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.proxy.ThreadlessPool')
    @mock.patch('proxy.proxy.Listener')
    def test_enable_devtools(
            self,
            mock_listener: mock.Mock,
            mock_executor_pool: mock.Mock,
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
        mock_args.local_executor = 0
        main()
        mock_load_plugins.assert_called()
        self.assertEqual(
            mock_load_plugins.call_args_list[0][0][0], [
                bytes_(PLUGIN_DEVTOOLS_PROTOCOL),
                bytes_(PLUGIN_WEB_SERVER),
                bytes_(PLUGIN_HTTP_PROXY),
            ],
        )
        mock_parse_args.assert_called_once()
        # Currently --enable-devtools flag alone doesn't enable eventing core
        mock_event_manager.assert_not_called()
        if _env_threadless_compliant():
            mock_executor_pool.assert_called_once()
            mock_executor_pool.return_value.setup.assert_called_once()
        mock_acceptor_pool.assert_called_once()
        mock_acceptor_pool.return_value.setup.assert_called_once()
        mock_listener.return_value.setup.assert_called_once()

    @mock.patch('time.sleep')
    @mock.patch('proxy.common.plugins.Plugins.load')
    @mock.patch('proxy.common.flag.FlagParser.parse_args')
    @mock.patch('proxy.proxy.EventManager')
    @mock.patch('proxy.proxy.AcceptorPool')
    @mock.patch('proxy.proxy.ThreadlessPool')
    @mock.patch('proxy.proxy.Listener')
    @mock.patch('proxy.proxy.SshHttpProtocolHandler')
    @mock.patch('proxy.proxy.SshTunnelListener')
    def test_enable_ssh_tunnel(
            self,
            mock_ssh_tunnel_listener: mock.Mock,
            mock_ssh_http_proto_handler: mock.Mock,
            mock_listener: mock.Mock,
            mock_executor_pool: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_event_manager: mock.Mock,
            mock_parse_args: mock.Mock,
            mock_load_plugins: mock.Mock,
            mock_sleep: mock.Mock,
    ) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.enable_ssh_tunnel = True
        mock_args.local_executor = 0
        main()
        mock_load_plugins.assert_called()
        self.assertEqual(
            mock_load_plugins.call_args_list[0][0][0], [
                bytes_(PLUGIN_HTTP_PROXY),
            ],
        )
        mock_parse_args.assert_called_once()
        mock_event_manager.assert_not_called()
        if _env_threadless_compliant():
            mock_executor_pool.assert_called_once()
            mock_executor_pool.return_value.setup.assert_called_once()
        mock_acceptor_pool.assert_called_once()
        mock_acceptor_pool.return_value.setup.assert_called_once()
        mock_listener.return_value.setup.assert_called_once()
        mock_ssh_http_proto_handler.assert_called_once()
        mock_ssh_tunnel_listener.assert_called_once()
        mock_ssh_tunnel_listener.return_value.setup.assert_called_once()
        mock_ssh_tunnel_listener.return_value.start_port_forward.assert_called_once()
        mock_ssh_tunnel_listener.return_value.shutdown.assert_called_once()
        # shutdown will internally call stop port forward
        mock_ssh_tunnel_listener.return_value.stop_port_forward.assert_not_called()
