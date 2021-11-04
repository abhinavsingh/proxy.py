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
import argparse
import base64
import collections
import ipaddress
import multiprocessing
import os
import socket
import sys
import time
import logging
import importlib
import inspect

from types import TracebackType
from typing import Dict, List, Optional, Any, Tuple, Type, Union, cast

from proxy.core.acceptor.work import Work

from .common.utils import bytes_, text_, setup_logger
from .common.types import IpAddress
from .common.version import __version__
from .core.acceptor import AcceptorPool
from .http.handler import HttpProtocolHandler
from .core.event import EventManager
from .common.flag import flags
from .common.constants import COMMA, DEFAULT_DATA_DIRECTORY_PATH, PLUGIN_PROXY_AUTH
from .common.constants import DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HEADERS
from .common.constants import DEFAULT_DISABLE_HTTP_PROXY, DEFAULT_NUM_WORKERS
from .common.constants import DEFAULT_ENABLE_DASHBOARD, DEFAULT_ENABLE_DEVTOOLS
from .common.constants import DEFAULT_ENABLE_STATIC_SERVER, DEFAULT_ENABLE_WEB_SERVER
from .common.constants import DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_LOG_LEVEL
from .common.constants import DEFAULT_OPEN_FILE_LIMIT, DEFAULT_PID_FILE, DEFAULT_PLUGINS
from .common.constants import DEFAULT_VERSION, DOT, PLUGIN_DASHBOARD, PLUGIN_DEVTOOLS_PROTOCOL
from .common.constants import PLUGIN_HTTP_PROXY, PLUGIN_INSPECT_TRAFFIC, PLUGIN_PAC_FILE
from .common.constants import PLUGIN_WEB_SERVER, PY2_DEPRECATION_MESSAGE, DEFAULT_ENABLE_EVENTS

if os.name != 'nt':
    import resource

logger = logging.getLogger(__name__)


flags.add_argument(
    '--pid-file',
    type=str,
    default=DEFAULT_PID_FILE,
    help='Default: None. Save parent process ID to a file.',
)
flags.add_argument(
    '--version',
    '-v',
    action='store_true',
    default=DEFAULT_VERSION,
    help='Prints proxy.py version.',
)
flags.add_argument(
    '--disable-http-proxy',
    action='store_true',
    default=DEFAULT_DISABLE_HTTP_PROXY,
    help='Default: False.  Whether to disable proxy.HttpProxyPlugin.',
)
flags.add_argument(
    '--enable-dashboard',
    action='store_true',
    default=DEFAULT_ENABLE_DASHBOARD,
    help='Default: False.  Enables proxy.py dashboard.',
)
flags.add_argument(
    '--enable-devtools',
    action='store_true',
    default=DEFAULT_ENABLE_DEVTOOLS,
    help='Default: False.  Enables integration with Chrome Devtool Frontend. Also see --devtools-ws-path.',
)
flags.add_argument(
    '--enable-static-server',
    action='store_true',
    default=DEFAULT_ENABLE_STATIC_SERVER,
    help='Default: False.  Enable inbuilt static file server. '
    'Optionally, also use --static-server-dir to serve static content '
    'from custom directory.  By default, static file server serves '
    'out of installed proxy.py python module folder.',
)
flags.add_argument(
    '--enable-web-server',
    action='store_true',
    default=DEFAULT_ENABLE_WEB_SERVER,
    help='Default: False.  Whether to enable proxy.HttpWebServerPlugin.',
)
flags.add_argument(
    '--enable-events',
    action='store_true',
    default=DEFAULT_ENABLE_EVENTS,
    help='Default: False.  Enables core to dispatch lifecycle events. '
    'Plugins can be used to subscribe for core events.',
)
flags.add_argument(
    '--log-level',
    type=str,
    default=DEFAULT_LOG_LEVEL,
    help='Valid options: DEBUG, INFO (default), WARNING, ERROR, CRITICAL. '
    'Both upper and lowercase values are allowed. '
    'You may also simply use the leading character e.g. --log-level d',
)
flags.add_argument(
    '--log-file',
    type=str,
    default=DEFAULT_LOG_FILE,
    help='Default: sys.stdout. Log file destination.',
)
flags.add_argument(
    '--log-format',
    type=str,
    default=DEFAULT_LOG_FORMAT,
    help='Log format for Python logger.',
)
flags.add_argument(
    '--open-file-limit',
    type=int,
    default=DEFAULT_OPEN_FILE_LIMIT,
    help='Default: 1024. Maximum number of files (TCP connections) '
    'that proxy.py can open concurrently.',
)
flags.add_argument(
    '--plugins',
    type=str,
    default=DEFAULT_PLUGINS,
    help='Comma separated plugins',
)


class Proxy:
    """Context manager to control core AcceptorPool server lifecycle.

    By default, AcceptorPool is started with HttpProtocolHandler worker class
    i.e. we are only expecting HTTP traffic to flow between clients and server.

    Optionally, also initialize a global event queue.
    It is a multiprocess safe queue which can be used to build pubsub patterns
    for message sharing or signaling.
    """

    def __init__(self, input_args: Optional[List[str]], **opts: Any) -> None:
        self.flags = Proxy.initialize(input_args, **opts)
        self.pool: Optional[AcceptorPool] = None
        # TODO(abhinavsingh): Allow users to override the worker class itself
        # e.g. A clear text protocol. Or imagine a TelnetProtocolHandler instead
        # of default HttpProtocolHandler.
        self.work_klass: Type[Work] = HttpProtocolHandler
        self.event_manager: Optional[EventManager] = None

    def write_pid_file(self) -> None:
        if self.flags.pid_file is not None:
            # TODO(abhinavsingh): Multiple instances of proxy.py running on
            # same host machine will currently result in overwriting the PID file
            with open(self.flags.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))

    def delete_pid_file(self) -> None:
        if self.flags.pid_file and os.path.exists(self.flags.pid_file):
            os.remove(self.flags.pid_file)

    def __enter__(self) -> 'Proxy':
        if self.flags.enable_events:
            logger.info('Core Event enabled')
            self.event_manager = EventManager()
            self.event_manager.start_event_dispatcher()
        self.pool = AcceptorPool(
            flags=self.flags,
            work_klass=self.work_klass,
            event_queue=self.event_manager.event_queue if self.event_manager is not None else None,
        )
        self.pool.setup()
        self.write_pid_file()
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType],
    ) -> None:
        assert self.pool
        self.pool.shutdown()
        if self.flags.enable_events:
            assert self.event_manager is not None
            self.event_manager.stop_event_dispatcher()
        self.delete_pid_file()

    @staticmethod
    def initialize(
        input_args: Optional[List[str]]
        = None, **opts: Any,
    ) -> argparse.Namespace:
        if input_args is None:
            input_args = []

        if not Proxy.is_py3():
            print(PY2_DEPRECATION_MESSAGE)
            sys.exit(1)

        # Discover flags from requested plugin.
        # This also surface external plugin flags under --help
        for i, f in enumerate(input_args):
            if f == '--plugin':
                Proxy.import_plugin(bytes_(input_args[i + 1]))

        # Parse flags
        args = flags.parse_args(input_args)

        # Print version and exit
        if args.version:
            print(__version__)
            sys.exit(0)

        # Setup logging module
        setup_logger(args.log_file, args.log_level, args.log_format)

        # Setup limits
        Proxy.set_open_file_limit(args.open_file_limit)

        # Load plugins
        default_plugins = Proxy.get_default_plugins(args)

        # Load default plugins along with user provided --plugins
        plugins = Proxy.load_plugins(
            [bytes_(p) for p in collections.OrderedDict(default_plugins).keys()] +
            [
                p if isinstance(p, type) else bytes_(p)
                for p in opts.get('plugins', args.plugins.split(text_(COMMA)))
            ],
        )

        # proxy.py currently cannot serve over HTTPS and also perform TLS interception
        # at the same time.  Check if user is trying to enable both feature
        # at the same time.
        if (args.cert_file and args.key_file) and \
                (args.ca_key_file and args.ca_cert_file and args.ca_signing_key_file):
            print(
                'You can either enable end-to-end encryption OR TLS interception,'
                'not both together.',
            )
            sys.exit(1)

        # Generate auth_code required for basic authentication if enabled
        auth_code = None
        if args.basic_auth:
            auth_code = base64.b64encode(bytes_(args.basic_auth))

        # https://github.com/python/mypy/issues/5865
        #
        # def option(t: object, key: str, default: Any) -> Any:
        #     return cast(t, opts.get(key, default))

        args.plugins = plugins
        args.auth_code = cast(
            Optional[bytes],
            opts.get(
                'auth_code',
                auth_code,
            ),
        )
        args.server_recvbuf_size = cast(
            int,
            opts.get(
                'server_recvbuf_size',
                args.server_recvbuf_size,
            ),
        )
        args.client_recvbuf_size = cast(
            int,
            opts.get(
                'client_recvbuf_size',
                args.client_recvbuf_size,
            ),
        )
        args.pac_file = cast(
            Optional[str], opts.get(
                'pac_file', bytes_(
                    args.pac_file,
                ),
            ),
        )
        args.pac_file_url_path = cast(
            Optional[bytes], opts.get(
                'pac_file_url_path', bytes_(
                    args.pac_file_url_path,
                ),
            ),
        )
        disabled_headers = cast(
            Optional[List[bytes]], opts.get(
                'disable_headers', [
                    header.lower()
                    for header in bytes_(args.disable_headers).split(COMMA)
                    if header.strip() != b''
                ],
            ),
        )
        args.disable_headers = disabled_headers if disabled_headers is not None else DEFAULT_DISABLE_HEADERS
        args.certfile = cast(
            Optional[str], opts.get(
                'cert_file', args.cert_file,
            ),
        )
        args.keyfile = cast(Optional[str], opts.get('key_file', args.key_file))
        args.ca_key_file = cast(
            Optional[str], opts.get(
                'ca_key_file', args.ca_key_file,
            ),
        )
        args.ca_cert_file = cast(
            Optional[str], opts.get(
                'ca_cert_file', args.ca_cert_file,
            ),
        )
        args.ca_signing_key_file = cast(
            Optional[str],
            opts.get(
                'ca_signing_key_file',
                args.ca_signing_key_file,
            ),
        )
        args.ca_file = cast(
            Optional[str],
            opts.get(
                'ca_file',
                args.ca_file,
            ),
        )
        args.hostname = cast(
            IpAddress,
            opts.get('hostname', ipaddress.ip_address(args.hostname)),
        )
        args.family = socket.AF_INET6 if args.hostname.version == 6 else socket.AF_INET
        args.port = cast(int, opts.get('port', args.port))
        args.backlog = cast(int, opts.get('backlog', args.backlog))
        num_workers = opts.get('num_workers', args.num_workers)
        num_workers = num_workers if num_workers is not None else DEFAULT_NUM_WORKERS
        args.num_workers = cast(
            int, num_workers if num_workers > 0 else multiprocessing.cpu_count(),
        )
        args.static_server_dir = cast(
            str,
            opts.get(
                'static_server_dir',
                args.static_server_dir,
            ),
        )
        args.enable_static_server = cast(
            bool,
            opts.get(
                'enable_static_server',
                args.enable_static_server,
            ),
        )
        args.devtools_ws_path = cast(
            bytes,
            opts.get(
                'devtools_ws_path',
                getattr(args, 'devtools_ws_path', DEFAULT_DEVTOOLS_WS_PATH),
            ),
        )
        args.timeout = cast(int, opts.get('timeout', args.timeout))
        args.threadless = cast(bool, opts.get('threadless', args.threadless))
        args.enable_events = cast(
            bool,
            opts.get(
                'enable_events',
                args.enable_events,
            ),
        )
        args.pid_file = cast(
            Optional[str], opts.get(
                'pid_file', args.pid_file,
            ),
        )

        args.proxy_py_data_dir = DEFAULT_DATA_DIRECTORY_PATH
        os.makedirs(args.proxy_py_data_dir, exist_ok=True)

        ca_cert_dir = opts.get('ca_cert_dir', args.ca_cert_dir)
        args.ca_cert_dir = cast(Optional[str], ca_cert_dir)
        if args.ca_cert_dir is None:
            args.ca_cert_dir = os.path.join(
                args.proxy_py_data_dir, 'certificates',
            )
            os.makedirs(args.ca_cert_dir, exist_ok=True)

        return args

    @staticmethod
    def load_plugins(
        plugins: List[Union[bytes, type]],
    ) -> Dict[bytes, List[type]]:
        """Accepts a comma separated list of Python modules and returns
        a list of respective Python classes."""
        p: Dict[bytes, List[type]] = {
            b'HttpProtocolHandlerPlugin': [],
            b'HttpProxyBasePlugin': [],
            b'HttpWebServerBasePlugin': [],
            b'ProxyDashboardWebsocketPlugin': [],
        }
        for plugin_ in plugins:
            klass, module_name = Proxy.import_plugin(plugin_)
            if klass is None and module_name is None:
                continue
            mro = list(inspect.getmro(klass))
            mro.reverse()
            iterator = iter(mro)
            while next(iterator) is not abc.ABC:
                pass
            base_klass = next(iterator)
            if klass not in p[bytes_(base_klass.__name__)]:
                p[bytes_(base_klass.__name__)].append(klass)
            logger.info('Loaded plugin %s.%s', module_name, klass.__name__)
        return p

    @staticmethod
    def import_plugin(plugin: Union[bytes, type]) -> Any:
        if isinstance(plugin, type):
            module_name = '__main__'
            klass = plugin
        else:
            plugin_ = text_(plugin.strip())
            if plugin_ == '':
                return (None, None)
            module_name, klass_name = plugin_.rsplit(text_(DOT), 1)
            klass = getattr(
                importlib.import_module(
                    module_name.replace(
                        os.path.sep, text_(DOT),
                    ),
                ),
                klass_name,
            )
        return (klass, module_name)

    @staticmethod
    def get_default_plugins(
            args: argparse.Namespace,
    ) -> List[Tuple[str, bool]]:
        # Prepare list of plugins to load based upon
        # --enable-*, --disable-* and --basic-auth flags.
        default_plugins: List[Tuple[str, bool]] = []
        if args.basic_auth is not None:
            default_plugins.append((PLUGIN_PROXY_AUTH, True))
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
        return default_plugins

    @staticmethod
    def is_py3() -> bool:
        """Exists only to avoid mocking sys.version_info in tests."""
        return sys.version_info[0] != 2

    @staticmethod
    def set_open_file_limit(soft_limit: int) -> None:
        """Configure open file description soft limit on supported OS."""
        if os.name != 'nt':  # resource module not available on Windows OS
            curr_soft_limit, curr_hard_limit = resource.getrlimit(
                resource.RLIMIT_NOFILE,
            )
            if curr_soft_limit < soft_limit < curr_hard_limit:
                resource.setrlimit(
                    resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit),
                )
                logger.debug(
                    'Open file soft limit set to %d', soft_limit,
                )


def main(
        input_args: Optional[List[str]] = None,
        **opts: Any,
) -> None:
    try:
        with Proxy(input_args=input_args, **opts) as proxy:
            assert proxy.pool is not None
            logger.info(
                'Listening on %s:%d' %
                (proxy.pool.flags.hostname, proxy.pool.flags.port),
            )
            # TODO: Introduce cron feature
            # https://github.com/abhinavsingh/proxy.py/issues/392
            #
            # TODO: Introduce ability to publish
            # adhoc events which can modify behaviour of server
            # at runtime.  Example, updating flags, plugin
            # configuration etc.
            #
            # TODO: Python shell within running proxy.py environment
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


def entry_point() -> None:
    main(input_args=sys.argv[1:])
