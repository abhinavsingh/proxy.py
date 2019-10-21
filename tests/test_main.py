
class TestMain(unittest.TestCase):

    @staticmethod
    def mock_default_args(mock_args: mock.Mock) -> None:
        mock_args.version = False
        mock_args.cert_file = proxy.DEFAULT_CERT_FILE
        mock_args.key_file = proxy.DEFAULT_KEY_FILE
        mock_args.ca_key_file = proxy.DEFAULT_CA_KEY_FILE
        mock_args.ca_cert_file = proxy.DEFAULT_CA_CERT_FILE
        mock_args.ca_signing_key_file = proxy.DEFAULT_CA_SIGNING_KEY_FILE
        mock_args.pid_file = proxy.DEFAULT_PID_FILE
        mock_args.log_file = proxy.DEFAULT_LOG_FILE
        mock_args.log_level = proxy.DEFAULT_LOG_LEVEL
        mock_args.log_format = proxy.DEFAULT_LOG_FORMAT
        mock_args.basic_auth = proxy.DEFAULT_BASIC_AUTH
        mock_args.hostname = proxy.DEFAULT_IPV6_HOSTNAME
        mock_args.port = proxy.DEFAULT_PORT
        mock_args.num_workers = proxy.DEFAULT_NUM_WORKERS
        mock_args.disable_http_proxy = proxy.DEFAULT_DISABLE_HTTP_PROXY
        mock_args.enable_web_server = proxy.DEFAULT_ENABLE_WEB_SERVER
        mock_args.pac_file = proxy.DEFAULT_PAC_FILE
        mock_args.plugins = proxy.DEFAULT_PLUGINS
        mock_args.server_recvbuf_size = proxy.DEFAULT_SERVER_RECVBUF_SIZE
        mock_args.client_recvbuf_size = proxy.DEFAULT_CLIENT_RECVBUF_SIZE
        mock_args.open_file_limit = proxy.DEFAULT_OPEN_FILE_LIMIT
        mock_args.enable_static_server = proxy.DEFAULT_ENABLE_STATIC_SERVER
        mock_args.enable_devtools = proxy.DEFAULT_ENABLE_DEVTOOLS
        mock_args.devtools_event_queue = None
        mock_args.devtools_ws_path = proxy.DEFAULT_DEVTOOLS_WS_PATH
        mock_args.timeout = proxy.DEFAULT_TIMEOUT
        mock_args.threadless = proxy.DEFAULT_THREADLESS
        mock_args.enable_events = proxy.DEFAULT_ENABLE_EVENTS
        mock_args.events_queue = proxy.DEFAULT_EVENTS_QUEUE

    @mock.patch('time.sleep')
    @mock.patch('proxy.load_plugins')
    @mock.patch('proxy.init_parser')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.Flags')
    @mock.patch('proxy.AcceptorPool')
    @mock.patch('proxy.logging.basicConfig')
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
        proxy.main([])

        mock_init_parser.assert_called()
        mock_init_parser.return_value.parse_args.called_with([])

        mock_load_plugins.assert_called_with(b'proxy.HttpProxyPlugin,')
        mock_logging_config.assert_called_with(
            level=logging.INFO,
            format=proxy.DEFAULT_LOG_FORMAT
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
                header.lower() for header in proxy.bytes_(
                    mock_args.disable_headers).split(proxy.COMMA) if header.strip() != b''],
            static_server_dir=mock_args.static_server_dir,
            enable_static_server=mock_args.enable_static_server,
            devtools_event_queue=None,
            devtools_ws_path=proxy.DEFAULT_DEVTOOLS_WS_PATH,
            timeout=proxy.DEFAULT_TIMEOUT,
            threadless=proxy.DEFAULT_THREADLESS,
            enable_events=proxy.DEFAULT_ENABLE_EVENTS,
            events_queue=proxy.DEFAULT_EVENTS_QUEUE,
        )
        mock_acceptor_pool.assert_called_with(
            flags=mock_protocol_config.return_value,
            work_klass=proxy.ProtocolHandler,
        )
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_acceptor_pool.return_value.shutdown.assert_called()
        mock_sleep.assert_called_with(1)

    @mock.patch('time.sleep')
    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.init_parser')
    @mock.patch('proxy.AcceptorPool')
    def test_pid_file_is_written_and_removed(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_init_parser: mock.Mock,
            mock_open: mock.Mock,
            mock_exists: mock.Mock,
            mock_remove: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        pid_file = get_temp_file('proxy.pid')
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_args = mock_init_parser.return_value.parse_args.return_value
        self.mock_default_args(mock_args)
        mock_args.pid_file = pid_file
        proxy.main(['--pid-file', pid_file])
        mock_init_parser.assert_called()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()
        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            proxy.bytes_(os.getpid()))
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('time.sleep')
    @mock.patch('proxy.Flags')
    @mock.patch('proxy.AcceptorPool')
    def test_basic_auth(
            self,
            mock_acceptor_pool: mock.Mock,
            mock_protocol_config: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        proxy.main(['--basic-auth', 'user:pass'])
        flags = mock_protocol_config.return_value
        mock_acceptor_pool.assert_called_with(
            flags=flags,
            work_klass=proxy.ProtocolHandler)
        self.assertEqual(mock_protocol_config.call_args[1]['auth_code'], b'Basic dXNlcjpwYXNz')

    @mock.patch('builtins.print')
    def test_main_version(
            self,
            mock_print: mock.Mock) -> None:
        with self.assertRaises(SystemExit):
            proxy.main(['--version'])
            mock_print.assert_called_with(proxy.text_(proxy.version))

    @mock.patch('time.sleep')
    @mock.patch('builtins.print')
    @mock.patch('proxy.AcceptorPool')
    @mock.patch('proxy.is_py3')
    def test_main_py3_runs(
            self,
            mock_is_py3: mock.Mock,
            mock_acceptor_pool: mock.Mock,
            mock_print: mock.Mock,
            mock_sleep: mock.Mock) -> None:
        mock_sleep.side_effect = KeyboardInterrupt()
        mock_is_py3.return_value = True
        proxy.main([])
        mock_is_py3.assert_called()
        mock_print.assert_not_called()
        mock_acceptor_pool.assert_called()
        mock_acceptor_pool.return_value.setup.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.is_py3')
    def test_main_py2_exit(
            self,
            mock_is_py3: mock.Mock,
            mock_print: mock.Mock) -> None:
        proxy.UNDER_TEST = False
        mock_is_py3.return_value = False
        with self.assertRaises(SystemExit):
            proxy.main([])
            mock_print.assert_called_with('DEPRECATION')
        mock_is_py3.assert_called()


@unittest.skipIf(
    os.name == 'nt',
    'Open file limit tests disabled for Windows')
class TestSetOpenFileLimit(unittest.TestCase):

    @mock.patch('resource.getrlimit', return_value=(128, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock) -> None:
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_called_with(resource.RLIMIT_NOFILE, (256, 1024))

    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock) -> None:
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()

    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called_coz_upper_bound_check(
            self,
            mock_set_rlimit: mock.Mock,
            mock_get_rlimit: mock.Mock) -> None:
        proxy.set_open_file_limit(1024)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()
