# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import base64
import importlib
import inspect
import ipaddress
import logging
import multiprocessing
import os
import sys
import time
from typing import Dict, List, Optional

from .common.flags import Flags, init_parser
from .common.utils import text_, bytes_
from .common.types import DictQueueType
from .common.constants import DOT, COMMA
from .common.constants import DEFAULT_LOG_FORMAT, DEFAULT_LOG_FILE, DEFAULT_LOG_LEVEL
from .common.version import __version__
from .core.acceptor import AcceptorPool
from .http.handler import ProtocolHandler

if os.name != 'nt':
    import resource

logger = logging.getLogger(__name__)


def is_py3() -> bool:
    """Exists only to avoid mocking sys.version_info in tests."""
    return sys.version_info[0] == 3


def set_open_file_limit(soft_limit: int) -> None:
    """Configure open file description soft limit on supported OS."""
    if os.name != 'nt':  # resource module not available on Windows OS
        curr_soft_limit, curr_hard_limit = resource.getrlimit(
            resource.RLIMIT_NOFILE)
        if curr_soft_limit < soft_limit < curr_hard_limit:
            resource.setrlimit(
                resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit))
            logger.debug(
                'Open file descriptor soft limit set to %d' %
                soft_limit)


def load_plugins(plugins: bytes) -> Dict[bytes, List[type]]:
    """Accepts a comma separated list of Python modules and returns
    a list of respective Python classes."""
    p: Dict[bytes, List[type]] = {
        b'HttpProtocolHandlerPlugin': [],
        b'HttpProxyBasePlugin': [],
        b'HttpWebServerBasePlugin': [],
    }
    for plugin_ in plugins.split(COMMA):
        plugin = text_(plugin_.strip())
        if plugin == '':
            continue
        module_name, klass_name = plugin.rsplit(text_(DOT), 1)
        klass = getattr(
            importlib.import_module(module_name.replace(os.path.sep, text_(DOT))),
            klass_name)
        base_klass = inspect.getmro(klass)[1]
        p[bytes_(base_klass.__name__)].append(klass)
        logger.info(
            'Loaded %s %s.%s',
            'plugin' if klass.__name__ != 'HttpWebServerRouteHandler' else 'route',
            module_name,
            # HttpWebServerRouteHandler route decorator adds a special
            # staticmethod to return decorated function name
            klass.__name__ if klass.__name__ != 'HttpWebServerRouteHandler' else klass.name())
    return p


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


def main(input_args: List[str]) -> None:
    if not is_py3():
        print(
            'DEPRECATION: "develop" branch no longer supports Python 2.7.  Kindly upgrade to Python 3+. '
            'If for some reasons you cannot upgrade, consider using "master" branch or simply '
            '"pip install proxy.py==0.3".'
            '\n\n'
            'DEPRECATION: Python 2.7 will reach the end of its life on January 1st, 2020. '
            'Please upgrade your Python as Python 2.7 won\'t be maintained after that date. '
            'A future version of pip will drop support for Python 2.7.')
        sys.exit(1)

    args = init_parser().parse_args(input_args)

    if args.version:
        print(__version__)
        sys.exit(0)

    if (args.cert_file and args.key_file) and \
            (args.ca_key_file and args.ca_cert_file and args.ca_signing_key_file):
        print('You can either enable end-to-end encryption OR TLS interception,'
              'not both together.')
        sys.exit(1)

    try:
        setup_logger(args.log_file, args.log_level, args.log_format)
        set_open_file_limit(args.open_file_limit)

        auth_code = None
        if args.basic_auth:
            auth_code = b'Basic %s' % base64.b64encode(bytes_(args.basic_auth))

        default_plugins = ''
        devtools_event_queue: Optional[DictQueueType] = None
        events_queue: Optional[DictQueueType] = None
        if args.enable_devtools:
            default_plugins += 'proxy.http.devtools.DevtoolsProtocolPlugin,'
            default_plugins += 'proxy.http.server.HttpWebServerPlugin,'
        if not args.disable_http_proxy:
            default_plugins += 'proxy.http.proxy.HttpProxyPlugin,'
        if args.enable_web_server or \
                args.pac_file is not None or \
                args.enable_static_server:
            if 'proxy.http.server.HttpWebServerPlugin' not in default_plugins:
                default_plugins += 'proxy.http.server.HttpWebServerPlugin,'
        if args.enable_devtools:
            default_plugins += 'proxy.http.devtools.DevtoolsWebsocketPlugin,'
            devtools_event_queue = multiprocessing.Manager().Queue()
        if args.pac_file is not None:
            default_plugins += 'proxy.http.server.HttpWebServerPacFilePlugin,'
        if args.enable_events:
            events_queue = multiprocessing.Manager().Queue()

        flags = Flags(
            auth_code=auth_code,
            server_recvbuf_size=args.server_recvbuf_size,
            client_recvbuf_size=args.client_recvbuf_size,
            pac_file=bytes_(args.pac_file),
            pac_file_url_path=bytes_(args.pac_file_url_path),
            disable_headers=[
                header.lower() for header in bytes_(
                    args.disable_headers).split(COMMA) if header.strip() != b''],
            certfile=args.cert_file,
            keyfile=args.key_file,
            ca_cert_dir=args.ca_cert_dir,
            ca_key_file=args.ca_key_file,
            ca_cert_file=args.ca_cert_file,
            ca_signing_key_file=args.ca_signing_key_file,
            hostname=ipaddress.ip_address(args.hostname),
            port=args.port,
            backlog=args.backlog,
            num_workers=args.num_workers,
            static_server_dir=args.static_server_dir,
            enable_static_server=args.enable_static_server,
            devtools_event_queue=devtools_event_queue,
            devtools_ws_path=args.devtools_ws_path,
            timeout=args.timeout,
            threadless=args.threadless,
            enable_events=args.enable_events,
            events_queue=events_queue)

        flags.plugins = load_plugins(
            bytes_(
                '%s%s' %
                (default_plugins, args.plugins)))

        acceptor_pool = AcceptorPool(
            flags=flags,
            work_klass=ProtocolHandler
        )

        if args.pid_file:
            with open(args.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))

        try:
            acceptor_pool.setup()
            # TODO: Introduce cron feature instead of mindless sleep
            while True:
                time.sleep(1)
        except Exception as e:
            logger.exception('exception', exc_info=e)
        finally:
            acceptor_pool.shutdown()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        if args.pid_file and os.path.exists(args.pid_file):
            os.remove(args.pid_file)


def entry_point() -> None:
    main(sys.argv[1:])
