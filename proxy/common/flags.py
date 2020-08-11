# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import abc
import logging
import importlib
import collections
import argparse
import base64
import ipaddress
import os
import socket
import multiprocessing
import sys
import inspect

from typing import Optional, Dict, List, TypeVar, Type, cast, Any, Tuple, Union

from .types import IpAddress
from .utils import text_, bytes_
from .constants import DEFAULT_LOG_LEVEL, DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_BACKLOG, DEFAULT_BASIC_AUTH
from .constants import DEFAULT_TIMEOUT, DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HTTP_PROXY, DEFAULT_DISABLE_HEADERS
from .constants import DEFAULT_ENABLE_STATIC_SERVER, DEFAULT_ENABLE_EVENTS, DEFAULT_ENABLE_DEVTOOLS
from .constants import DEFAULT_ENABLE_WEB_SERVER, DEFAULT_THREADLESS, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE, DEFAULT_CA_FILE
from .constants import DEFAULT_CA_CERT_DIR, DEFAULT_CA_CERT_FILE, DEFAULT_CA_KEY_FILE, DEFAULT_CA_SIGNING_KEY_FILE
from .constants import DEFAULT_PAC_FILE_URL_PATH, DEFAULT_PAC_FILE, DEFAULT_PLUGINS, DEFAULT_PID_FILE, DEFAULT_PORT
from .constants import DEFAULT_NUM_WORKERS, DEFAULT_VERSION, DEFAULT_OPEN_FILE_LIMIT, DEFAULT_IPV6_HOSTNAME
from .constants import DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_CLIENT_RECVBUF_SIZE, DEFAULT_STATIC_SERVER_DIR
from .constants import DEFAULT_ENABLE_DASHBOARD, DEFAULT_DATA_DIRECTORY_PATH, COMMA, DOT
from .constants import PLUGIN_HTTP_PROXY, PLUGIN_WEB_SERVER, PLUGIN_PAC_FILE
from .constants import PLUGIN_DEVTOOLS_PROTOCOL, PLUGIN_DASHBOARD, PLUGIN_INSPECT_TRAFFIC
from .version import __version__

__homepage__ = 'https://github.com/abhinavsingh/proxy.py'

if os.name != 'nt':
    import resource

logger = logging.getLogger(__name__)

T = TypeVar('T', bound='Flags')


class Flags:
    """Contains all input flags and inferred input parameters."""

    def __init__(
            self,
            auth_code: Optional[bytes] = DEFAULT_BASIC_AUTH,
            server_recvbuf_size: int = DEFAULT_SERVER_RECVBUF_SIZE,
            client_recvbuf_size: int = DEFAULT_CLIENT_RECVBUF_SIZE,
            pac_file: Optional[str] = DEFAULT_PAC_FILE,
            pac_file_url_path: Optional[bytes] = DEFAULT_PAC_FILE_URL_PATH,
            plugins: Optional[Dict[bytes, List[type]]] = None,
            disable_headers: Optional[List[bytes]] = None,
            certfile: Optional[str] = None,
            keyfile: Optional[str] = None,
            ca_cert_dir: Optional[str] = None,
            ca_key_file: Optional[str] = None,
            ca_cert_file: Optional[str] = None,
            ca_signing_key_file: Optional[str] = None,
            ca_file: Optional[str] = None,
            num_workers: int = 0,
            hostname: IpAddress = DEFAULT_IPV6_HOSTNAME,
            port: int = DEFAULT_PORT,
            backlog: int = DEFAULT_BACKLOG,
            static_server_dir: str = DEFAULT_STATIC_SERVER_DIR,
            enable_static_server: bool = DEFAULT_ENABLE_STATIC_SERVER,
            devtools_ws_path: bytes = DEFAULT_DEVTOOLS_WS_PATH,
            timeout: int = DEFAULT_TIMEOUT,
            threadless: bool = DEFAULT_THREADLESS,
            enable_events: bool = DEFAULT_ENABLE_EVENTS,
            pid_file: Optional[str] = DEFAULT_PID_FILE) -> None:
        self.pid_file = pid_file
        self.threadless = threadless
        self.timeout = timeout
        self.auth_code = auth_code
        self.server_recvbuf_size = server_recvbuf_size
        self.client_recvbuf_size = client_recvbuf_size
        self.pac_file = pac_file
        self.pac_file_url_path = pac_file_url_path
        if plugins is None:
            plugins = {}
        self.plugins: Dict[bytes, List[type]] = plugins
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS
        self.disable_headers = disable_headers
        self.certfile: Optional[str] = certfile
        self.keyfile: Optional[str] = keyfile
        self.ca_key_file: Optional[str] = ca_key_file
        self.ca_cert_file: Optional[str] = ca_cert_file
        self.ca_signing_key_file: Optional[str] = ca_signing_key_file
        self.ca_file = ca_file
        self.num_workers: int = num_workers if num_workers > 0 else multiprocessing.cpu_count()
        self.hostname: IpAddress = hostname
        self.family: socket.AddressFamily = socket.AF_INET6 if hostname.version == 6 else socket.AF_INET
        self.port: int = port
        self.backlog: int = backlog

        self.enable_static_server: bool = enable_static_server
        self.static_server_dir: str = static_server_dir
        self.devtools_ws_path: bytes = devtools_ws_path
        self.enable_events: bool = enable_events

        self.proxy_py_data_dir = DEFAULT_DATA_DIRECTORY_PATH
        os.makedirs(self.proxy_py_data_dir, exist_ok=True)

        self.ca_cert_dir: Optional[str] = ca_cert_dir
        if self.ca_cert_dir is None:
            self.ca_cert_dir = os.path.join(
                self.proxy_py_data_dir, 'certificates')
            os.makedirs(self.ca_cert_dir, exist_ok=True)

    def tls_interception_enabled(self) -> bool:
        return self.ca_key_file is not None and \
            self.ca_cert_dir is not None and \
            self.ca_signing_key_file is not None and \
            self.ca_cert_file is not None

    def encryption_enabled(self) -> bool:
        return self.keyfile is not None and \
            self.certfile is not None

    @classmethod
    def initialize(
            cls: Type[T],
            input_args: Optional[List[str]],
            **opts: Any) -> T:
        if not Flags.is_py3():
            print(
                'DEPRECATION: "develop" branch no longer supports Python 2.7.  Kindly upgrade to Python 3+. '
                'If for some reasons you cannot upgrade, consider using "master" branch or simply '
                '"pip install proxy.py==0.3".'
                '\n\n'
                'DEPRECATION: Python 2.7 will reach the end of its life on January 1st, 2020. '
                'Please upgrade your Python as Python 2.7 won\'t be maintained after that date. '
                'A future version of pip will drop support for Python 2.7.')
            sys.exit(1)

        # Initialize core flags.
        parser = Flags.init_parser()
        # Parse flags
        args = parser.parse_args(input_args)

        # Print version and exit
        if args.version:
            print(__version__)
            sys.exit(0)

        # Setup logging module
        Flags.setup_logger(args.log_file, args.log_level, args.log_format)

        # Setup limits
        Flags.set_open_file_limit(args.open_file_limit)

        # Prepare list of plugins to load based upon --enable-* and --disable-*
        # flags
        default_plugins: List[Tuple[str, bool]] = []
        if args.enable_dashboard:
            default_plugins.append((PLUGIN_WEB_SERVER, True))
            args.enable_static_server = True
            default_plugins.append((PLUGIN_DASHBOARD, True))
            default_plugins.append((PLUGIN_INSPECT_TRAFFIC, True))
            args.enable_events = True
            args.enable_devtools = True
        if args.enable_devtools:
            default_plugins.append((PLUGIN_DEVTOOLS_PROTOCOL, True))
            default_plugins.append((PLUGIN_WEB_SERVER, True))
        if not args.disable_http_proxy:
            default_plugins.append((PLUGIN_HTTP_PROXY, True))
        if args.enable_web_server or \
                args.pac_file is not None or \
                args.enable_static_server:
            default_plugins.append((PLUGIN_WEB_SERVER, True))
        if args.pac_file is not None:
            default_plugins.append((PLUGIN_PAC_FILE, True))

        # Load default plugins along with user provided --plugins
        plugins = Flags.load_plugins(
            [bytes_(p) for p in collections.OrderedDict(default_plugins).keys()] +
            [p if isinstance(p, type) else bytes_(p) for p in opts.get('plugins', args.plugins.split(text_(COMMA)))]
        )

        # proxy.py currently cannot serve over HTTPS and perform TLS interception
        # at the same time.  Check if user is trying to enable both feature
        # at the same time.
        if (args.cert_file and args.key_file) and \
                (args.ca_key_file and args.ca_cert_file and args.ca_signing_key_file):
            print('You can either enable end-to-end encryption OR TLS interception,'
                  'not both together.')
            sys.exit(1)

        # Generate auth_code required for basic authentication if enabled
        auth_code = None
        if args.basic_auth:
            auth_code = b'Basic %s' % base64.b64encode(bytes_(args.basic_auth))

        return cls(
            auth_code=cast(Optional[bytes], opts.get('auth_code', auth_code)),
            server_recvbuf_size=cast(
                int,
                opts.get(
                    'server_recvbuf_size',
                    args.server_recvbuf_size)),
            client_recvbuf_size=cast(
                int,
                opts.get(
                    'client_recvbuf_size',
                    args.client_recvbuf_size)),
            pac_file=cast(
                Optional[str], opts.get(
                    'pac_file', bytes_(
                        args.pac_file))),
            pac_file_url_path=cast(
                Optional[bytes], opts.get(
                    'pac_file_url_path', bytes_(
                        args.pac_file_url_path))),
            disable_headers=cast(Optional[List[bytes]], opts.get('disable_headers', [
                header.lower() for header in bytes_(
                    args.disable_headers).split(COMMA) if header.strip() != b''])),
            certfile=cast(
                Optional[str], opts.get(
                    'cert_file', args.cert_file)),
            keyfile=cast(Optional[str], opts.get('key_file', args.key_file)),
            ca_cert_dir=cast(
                Optional[str], opts.get(
                    'ca_cert_dir', args.ca_cert_dir)),
            ca_key_file=cast(
                Optional[str], opts.get(
                    'ca_key_file', args.ca_key_file)),
            ca_cert_file=cast(
                Optional[str], opts.get(
                    'ca_cert_file', args.ca_cert_file)),
            ca_signing_key_file=cast(
                Optional[str],
                opts.get(
                    'ca_signing_key_file',
                    args.ca_signing_key_file)),
            ca_file=cast(
                Optional[str],
                opts.get(
                    'ca_file',
                    args.ca_file)),
            hostname=cast(IpAddress,
                          opts.get('hostname', ipaddress.ip_address(args.hostname))),
            port=cast(int, opts.get('port', args.port)),
            backlog=cast(int, opts.get('backlog', args.backlog)),
            num_workers=cast(int, opts.get('num_workers', args.num_workers)),
            static_server_dir=cast(
                str,
                opts.get(
                    'static_server_dir',
                    args.static_server_dir)),
            enable_static_server=cast(
                bool,
                opts.get(
                    'enable_static_server',
                    args.enable_static_server)),
            devtools_ws_path=cast(
                bytes,
                opts.get(
                    'devtools_ws_path',
                    args.devtools_ws_path)),
            timeout=cast(int, opts.get('timeout', args.timeout)),
            threadless=cast(bool, opts.get('threadless', args.threadless)),
            enable_events=cast(
                bool,
                opts.get(
                    'enable_events',
                    args.enable_events)),
            plugins=plugins,
            pid_file=cast(Optional[str], opts.get('pid_file', args.pid_file)))

    @staticmethod
    def init_parser() -> argparse.ArgumentParser:
        """Initializes and returns argument parser."""
        parser = argparse.ArgumentParser(
            description='proxy.py v%s' % __version__,
            epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__
        )
        # Argument names are ordered alphabetically.
        parser.add_argument(
            '--backlog',
            type=int,
            default=DEFAULT_BACKLOG,
            help='Default: 100. Maximum number of pending connections to proxy server')
        parser.add_argument(
            '--basic-auth',
            type=str,
            default=DEFAULT_BASIC_AUTH,
            help='Default: No authentication. Specify colon separated user:password '
                 'to enable basic authentication.')
        parser.add_argument(
            '--ca-key-file',
            type=str,
            default=DEFAULT_CA_KEY_FILE,
            help='Default: None. CA key to use for signing dynamically generated '
                 'HTTPS certificates.  If used, must also pass --ca-cert-file and --ca-signing-key-file'
        )
        parser.add_argument(
            '--ca-cert-dir',
            type=str,
            default=DEFAULT_CA_CERT_DIR,
            help='Default: ~/.proxy.py. Directory to store dynamically generated certificates. '
                 'Also see --ca-key-file, --ca-cert-file and --ca-signing-key-file'
        )
        parser.add_argument(
            '--ca-cert-file',
            type=str,
            default=DEFAULT_CA_CERT_FILE,
            help='Default: None. Signing certificate to use for signing dynamically generated '
                 'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-signing-key-file'
        )
        parser.add_argument(
            '--ca-file',
            type=str,
            default=DEFAULT_CA_FILE,
            help='Default: None. Provide path to custom CA file for peer certificate validation. '
                 'Specially useful on MacOS.'
        )
        parser.add_argument(
            '--ca-signing-key-file',
            type=str,
            default=DEFAULT_CA_SIGNING_KEY_FILE,
            help='Default: None. CA signing key to use for dynamic generation of '
                 'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-cert-file'
        )
        parser.add_argument(
            '--cert-file',
            type=str,
            default=DEFAULT_CERT_FILE,
            help='Default: None. Server certificate to enable end-to-end TLS encryption with clients. '
                 'If used, must also pass --key-file.'
        )
        parser.add_argument(
            '--client-recvbuf-size',
            type=int,
            default=DEFAULT_CLIENT_RECVBUF_SIZE,
            help='Default: 1 MB. Maximum amount of data received from the '
                 'client in a single recv() operation. Bump this '
                 'value for faster uploads at the expense of '
                 'increased RAM.')
        parser.add_argument(
            '--devtools-ws-path',
            type=str,
            default=DEFAULT_DEVTOOLS_WS_PATH,
            help='Default: /devtools.  Only applicable '
                 'if --enable-devtools is used.'
        )
        parser.add_argument(
            '--disable-headers',
            type=str,
            default=COMMA.join(DEFAULT_DISABLE_HEADERS),
            help='Default: None.  Comma separated list of headers to remove before '
                 'dispatching client request to upstream server.')
        parser.add_argument(
            '--disable-http-proxy',
            action='store_true',
            default=DEFAULT_DISABLE_HTTP_PROXY,
            help='Default: False.  Whether to disable proxy.HttpProxyPlugin.')
        parser.add_argument(
            '--enable-dashboard',
            action='store_true',
            default=DEFAULT_ENABLE_DASHBOARD,
            help='Default: False.  Enables proxy.py dashboard.'
        )
        parser.add_argument(
            '--enable-devtools',
            action='store_true',
            default=DEFAULT_ENABLE_DEVTOOLS,
            help='Default: False.  Enables integration with Chrome Devtool Frontend. Also see --devtools-ws-path.'
        )
        parser.add_argument(
            '--enable-events',
            action='store_true',
            default=DEFAULT_ENABLE_EVENTS,
            help='Default: False.  Enables core to dispatch lifecycle events. '
                 'Plugins can be used to subscribe for core events.'
        )
        parser.add_argument(
            '--enable-static-server',
            action='store_true',
            default=DEFAULT_ENABLE_STATIC_SERVER,
            help='Default: False.  Enable inbuilt static file server. '
                 'Optionally, also use --static-server-dir to serve static content '
                 'from custom directory.  By default, static file server serves '
                 'out of installed proxy.py python module folder.'
        )
        parser.add_argument(
            '--enable-web-server',
            action='store_true',
            default=DEFAULT_ENABLE_WEB_SERVER,
            help='Default: False.  Whether to enable proxy.HttpWebServerPlugin.')
        parser.add_argument(
            '--hostname',
            type=str,
            default=str(DEFAULT_IPV6_HOSTNAME),
            help='Default: ::1. Server IP address.')
        parser.add_argument(
            '--key-file',
            type=str,
            default=DEFAULT_KEY_FILE,
            help='Default: None. Server key file to enable end-to-end TLS encryption with clients. '
                 'If used, must also pass --cert-file.'
        )
        parser.add_argument(
            '--log-level',
            type=str,
            default=DEFAULT_LOG_LEVEL,
            help='Valid options: DEBUG, INFO (default), WARNING, ERROR, CRITICAL. '
                 'Both upper and lowercase values are allowed. '
                 'You may also simply use the leading character e.g. --log-level d')
        parser.add_argument('--log-file', type=str, default=DEFAULT_LOG_FILE,
                            help='Default: sys.stdout. Log file destination.')
        parser.add_argument('--log-format', type=str, default=DEFAULT_LOG_FORMAT,
                            help='Log format for Python logger.')
        parser.add_argument('--num-workers', type=int, default=DEFAULT_NUM_WORKERS,
                            help='Defaults to number of CPU cores.')
        parser.add_argument(
            '--open-file-limit',
            type=int,
            default=DEFAULT_OPEN_FILE_LIMIT,
            help='Default: 1024. Maximum number of files (TCP connections) '
                 'that proxy.py can open concurrently.')
        parser.add_argument(
            '--pac-file',
            type=str,
            default=DEFAULT_PAC_FILE,
            help='A file (Proxy Auto Configuration) or string to serve when '
                 'the server receives a direct file request. '
                 'Using this option enables proxy.HttpWebServerPlugin.')
        parser.add_argument(
            '--pac-file-url-path',
            type=str,
            default=text_(DEFAULT_PAC_FILE_URL_PATH),
            help='Default: %s. Web server path to serve the PAC file.' %
                 text_(DEFAULT_PAC_FILE_URL_PATH))
        parser.add_argument(
            '--pid-file',
            type=str,
            default=DEFAULT_PID_FILE,
            help='Default: None. Save parent process ID to a file.')
        parser.add_argument(
            '--plugins',
            type=str,
            default=DEFAULT_PLUGINS,
            help='Comma separated plugins')
        parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                            help='Default: 8899. Server port.')
        parser.add_argument(
            '--server-recvbuf-size',
            type=int,
            default=DEFAULT_SERVER_RECVBUF_SIZE,
            help='Default: 1 MB. Maximum amount of data received from the '
                 'server in a single recv() operation. Bump this '
                 'value for faster downloads at the expense of '
                 'increased RAM.')
        parser.add_argument(
            '--static-server-dir',
            type=str,
            default=DEFAULT_STATIC_SERVER_DIR,
            help='Default: "public" folder in directory where proxy.py is placed. '
                 'This option is only applicable when static server is also enabled. '
                 'See --enable-static-server.'
        )
        parser.add_argument(
            '--threadless',
            action='store_true',
            default=DEFAULT_THREADLESS,
            help='Default: False.  When disabled a new thread is spawned '
                 'to handle each client connection.'
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=DEFAULT_TIMEOUT,
            help='Default: ' + str(DEFAULT_TIMEOUT) +
                 '.  Number of seconds after which '
                 'an inactive connection must be dropped.  Inactivity is defined by no '
                 'data sent or received by the client.'
        )
        parser.add_argument(
            '--version',
            '-v',
            action='store_true',
            default=DEFAULT_VERSION,
            help='Prints proxy.py version.')
        return parser

    @staticmethod
    def set_open_file_limit(soft_limit: int) -> None:
        """Configure open file description soft limit on supported OS."""
        if os.name != 'nt':  # resource module not available on Windows OS
            curr_soft_limit, curr_hard_limit = resource.getrlimit(
                resource.RLIMIT_NOFILE)
            if curr_soft_limit < soft_limit < curr_hard_limit:
                resource.setrlimit(
                    resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit))
                logger.debug(
                    'Open file soft limit set to %d', soft_limit)

    @staticmethod
    def load_plugins(plugins: List[Union[bytes, type]]) -> Dict[bytes, List[type]]:
        """Accepts a comma separated list of Python modules and returns
        a list of respective Python classes."""
        p: Dict[bytes, List[type]] = {
            b'HttpProtocolHandlerPlugin': [],
            b'HttpProxyBasePlugin': [],
            b'HttpWebServerBasePlugin': [],
            b'ProxyDashboardWebsocketPlugin': []
        }
        for plugin_ in plugins:
            if isinstance(plugin_, type):
                module_name = None
                klass = plugin_
            else:
                plugin = text_(plugin_.strip())
                if plugin == '':
                    continue
                module_name, klass_name = plugin.rsplit(text_(DOT), 1)
                klass = getattr(
                    importlib.import_module(
                        module_name.replace(
                            os.path.sep, text_(DOT))),
                    klass_name)
            mro = list(inspect.getmro(klass))
            mro.reverse()
            iterator = iter(mro)
            while next(iterator) is not abc.ABC:
                pass
            base_klass = next(iterator)
            p[bytes_(base_klass.__name__)].append(klass)
            logger.info('Loaded plugin %s.%s', module_name, klass.__name__)
        return p

    @staticmethod
    def setup_logger(
            log_file: Optional[str] = DEFAULT_LOG_FILE,
            log_level: str = DEFAULT_LOG_LEVEL,
            log_format: str = DEFAULT_LOG_FORMAT) -> None:
        ll = getattr(
            logging,
            {'D': 'DEBUG',
             'I': 'INFO',
             'W': 'WARNING',
             'E': 'ERROR',
             'C': 'CRITICAL'}[log_level.upper()[0]])
        if log_file:
            logging.basicConfig(
                filename=log_file,
                filemode='a',
                level=ll,
                format=log_format)
        else:
            logging.basicConfig(level=ll, format=log_format)

    @staticmethod
    def is_py3() -> bool:
        """Exists only to avoid mocking sys.version_info in tests."""
        return sys.version_info[0] == 3
