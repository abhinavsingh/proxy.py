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
import sys
import base64
import socket
import argparse
import ipaddress
import collections
import multiprocessing

from typing import Optional, List, Any, cast

from .types import IpAddress
from .utils import text_, bytes_, is_py2, set_open_file_limit
from .utils import discover_plugins, load_plugins
from .constants import COMMA, DEFAULT_DATA_DIRECTORY_PATH, DEFAULT_NUM_WORKERS
from .constants import DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HEADERS, PY2_DEPRECATION_MESSAGE
from .constants import PLUGIN_DASHBOARD, PLUGIN_DEVTOOLS_PROTOCOL
from .constants import PLUGIN_HTTP_PROXY, PLUGIN_INSPECT_TRAFFIC, PLUGIN_PAC_FILE
from .constants import PLUGIN_WEB_SERVER, PLUGIN_PROXY_AUTH
from .logger import Logger

from .version import __version__

__homepage__ = 'https://github.com/abhinavsingh/proxy.py'


# TODO: Currently `initialize` staticmethod contains knowledge
# about several common flags defined by proxy.py core.

# This logic must be decoupled.  flags.add_argument must
# also provide a callback to resolve the final flag value
# based upon availability in input_args, **opts and
# default values.

# Supporting such a framework is complex but achievable.
# One problem is that resolution of certain flags
# can depend upon availability of other flags.

# This will lead us into dependency graph modeling domain.
class FlagParser:
    """Wrapper around argparse module.

    Import `flag.flags` and use `add_argument` API
    to define custom flags within respective Python files.

    Best Practice:
    1. Define flags at the top of your class files.
    2. DO NOT add flags within your class `__init__` method OR
       within class methods.  It MAY result into runtime exception,
       especially if your class is initialized multiple times or if
       class method registering the flag gets invoked multiple times.
    """

    def __init__(self) -> None:
        self.args: Optional[argparse.Namespace] = None
        self.actions: List[str] = []
        self.parser = argparse.ArgumentParser(
            description='proxy.py v%s' % __version__,
            epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__,
        )

    def add_argument(self, *args: Any, **kwargs: Any) -> argparse.Action:
        """Register a flag."""
        action = self.parser.add_argument(*args, **kwargs)
        self.actions.append(action.dest)
        return action

    def parse_args(
            self, input_args: Optional[List[str]],
    ) -> argparse.Namespace:
        """Parse flags from input arguments."""
        self.args = self.parser.parse_args(input_args)
        return self.args

    @staticmethod
    def initialize(
        input_args: Optional[List[str]]
        = None, **opts: Any,
    ) -> argparse.Namespace:
        if input_args is None:
            input_args = []

        if is_py2():
            print(PY2_DEPRECATION_MESSAGE)
            sys.exit(1)

        # Discover flags from requested plugin.
        # This will also surface external plugin flags
        # under --help.
        discover_plugins(input_args)

        # Parse flags
        args = flags.parse_args(input_args)

        # Print version and exit
        if args.version:
            print(__version__)
            sys.exit(0)

        # Setup logging module
        Logger.setup_logger(args.log_file, args.log_level, args.log_format)

        # Setup limits
        set_open_file_limit(args.open_file_limit)

        # Load plugins
        default_plugins = [
            bytes_(p)
            for p in FlagParser.get_default_plugins(args)
        ]
        extra_plugins = [
            p if isinstance(p, type) else bytes_(p)
            for p in opts.get('plugins', args.plugins.split(text_(COMMA)))
            if not (isinstance(p, str) and len(p) == 0)
        ]

        # Load default plugins along with user provided --plugins
        plugins = load_plugins(default_plugins + extra_plugins)

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
        # AF_UNIX is not available on Windows
        # See https://bugs.python.org/issue33408
        if os.name != 'nt':
            args.family = socket.AF_UNIX if args.unix_socket_path else (
                socket.AF_INET6 if args.hostname.version == 6 else socket.AF_INET
            )
        else:
            # FIXME: Not true for tests, as this value will be mock
            # It's a problem only on Windows.  Instead of a proper
            # test level fix, simply commenting this for now.
            # assert args.unix_socket_path is None
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
    def get_default_plugins(
            args: argparse.Namespace,
    ) -> List[str]:
        """Prepare list of plugins to load based upon
        --enable-*, --disable-* and --basic-auth flags.
        """
        default_plugins: List[str] = []
        if args.basic_auth is not None:
            default_plugins.append(PLUGIN_PROXY_AUTH)
        if hasattr(args, 'enable_dashboard') and args.enable_dashboard:
            default_plugins.append(PLUGIN_WEB_SERVER)
            args.enable_static_server = True
            default_plugins.append(PLUGIN_DASHBOARD)
            default_plugins.append(PLUGIN_INSPECT_TRAFFIC)
            args.enable_events = True
            args.enable_devtools = True
        if hasattr(args, 'enable_devtools') and args.enable_devtools:
            default_plugins.append(PLUGIN_DEVTOOLS_PROTOCOL)
            default_plugins.append(PLUGIN_WEB_SERVER)
        if not args.disable_http_proxy:
            default_plugins.append(PLUGIN_HTTP_PROXY)
        if args.enable_web_server or \
                args.pac_file is not None or \
                args.enable_static_server:
            default_plugins.append(PLUGIN_WEB_SERVER)
        if args.pac_file is not None:
            default_plugins.append(PLUGIN_PAC_FILE)
        return list(collections.OrderedDict.fromkeys(default_plugins).keys())


flags = FlagParser()
