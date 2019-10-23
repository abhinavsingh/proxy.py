# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import argparse
import ipaddress
import os
import socket
import multiprocessing
import pathlib

from typing import Optional, Union, Dict, List

from .utils import text_
from .types import DictQueueType
from .constants import DEFAULT_LOG_LEVEL, DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_BACKLOG, DEFAULT_BASIC_AUTH
from .constants import DEFAULT_TIMEOUT, DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HTTP_PROXY, DEFAULT_DISABLE_HEADERS
from .constants import DEFAULT_ENABLE_STATIC_SERVER, DEFAULT_ENABLE_EVENTS, DEFAULT_ENABLE_DEVTOOLS
from .constants import DEFAULT_ENABLE_WEB_SERVER, DEFAULT_THREADLESS, DEFAULT_CERT_FILE, DEFAULT_KEY_FILE
from .constants import DEFAULT_CA_CERT_DIR, DEFAULT_CA_CERT_FILE, DEFAULT_CA_KEY_FILE, DEFAULT_CA_SIGNING_KEY_FILE
from .constants import DEFAULT_PAC_FILE_URL_PATH, DEFAULT_PAC_FILE, DEFAULT_PLUGINS, DEFAULT_PID_FILE, DEFAULT_PORT
from .constants import DEFAULT_NUM_WORKERS, DEFAULT_VERSION, DEFAULT_OPEN_FILE_LIMIT, DEFAULT_IPV6_HOSTNAME
from .constants import DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_CLIENT_RECVBUF_SIZE, DEFAULT_STATIC_SERVER_DIR
from .constants import DEFAULT_EVENTS_QUEUE, COMMA
from .constants import __homepage__
from .version import __version__


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
        '--enable-devtools',
        action='store_true',
        default=DEFAULT_ENABLE_DEVTOOLS,
        help='Default: False.  Enables integration with Chrome Devtool Frontend.'
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
             'from public folder.'
    )
    parser.add_argument(
        '--enable-web-server',
        action='store_true',
        default=DEFAULT_ENABLE_WEB_SERVER,
        help='Default: False.  Whether to enable proxy.HttpWebServerPlugin.')
    parser.add_argument('--hostname',
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
        help='Default: ' + str(DEFAULT_TIMEOUT) + '.  Number of seconds after which '
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


class Flags:
    """Contains all input flags and inferred input parameters."""

    ROOT_DATA_DIR_NAME = '.proxy.py'
    GENERATED_CERTS_DIR_NAME = 'certificates'

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
            num_workers: int = 0,
            hostname: Union[ipaddress.IPv4Address,
                            ipaddress.IPv6Address] = DEFAULT_IPV6_HOSTNAME,
            port: int = DEFAULT_PORT,
            backlog: int = DEFAULT_BACKLOG,
            static_server_dir: str = DEFAULT_STATIC_SERVER_DIR,
            enable_static_server: bool = DEFAULT_ENABLE_STATIC_SERVER,
            devtools_event_queue: Optional[DictQueueType] = None,
            devtools_ws_path: bytes = DEFAULT_DEVTOOLS_WS_PATH,
            timeout: int = DEFAULT_TIMEOUT,
            threadless: bool = DEFAULT_THREADLESS,
            enable_events: bool = DEFAULT_ENABLE_EVENTS,
            events_queue: Optional[DictQueueType] = DEFAULT_EVENTS_QUEUE) -> None:
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
        self.num_workers: int = num_workers if num_workers > 0 else multiprocessing.cpu_count()
        self.hostname: Union[ipaddress.IPv4Address,
                             ipaddress.IPv6Address] = hostname
        self.family: socket.AddressFamily = socket.AF_INET6 if hostname.version == 6 else socket.AF_INET
        self.port: int = port
        self.backlog: int = backlog

        self.enable_static_server: bool = enable_static_server
        self.static_server_dir: str = static_server_dir

        self.devtools_event_queue: Optional[DictQueueType] = devtools_event_queue
        self.devtools_ws_path: bytes = devtools_ws_path

        self.enable_events: bool = enable_events
        self.events_queue: Optional[DictQueueType] = events_queue

        self.proxy_py_data_dir = os.path.join(
            str(pathlib.Path.home()), self.ROOT_DATA_DIR_NAME)
        os.makedirs(self.proxy_py_data_dir, exist_ok=True)

        self.ca_cert_dir: Optional[str] = ca_cert_dir
        if self.ca_cert_dir is None:
            self.ca_cert_dir = os.path.join(
                self.proxy_py_data_dir, self.GENERATED_CERTS_DIR_NAME)
            os.makedirs(self.ca_cert_dir, exist_ok=True)

    def tls_interception_enabled(self) -> bool:
        return self.ca_key_file is not None and \
            self.ca_cert_dir is not None and \
            self.ca_signing_key_file is not None and \
            self.ca_cert_file is not None

    def encryption_enabled(self) -> bool:
        return self.keyfile is not None and \
            self.certfile is not None
