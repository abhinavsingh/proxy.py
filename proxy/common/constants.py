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
import time
import pathlib
import secrets
import platform
import ipaddress
import sysconfig
from typing import Any, List

from .version import __version__


SYS_PLATFORM = platform.system()
IS_WINDOWS = SYS_PLATFORM == 'Windows'


def _env_threadless_compliant() -> bool:
    """Returns true for Python 3.8+ across all platforms
    except Windows."""
    return not IS_WINDOWS and sys.version_info >= (3, 8)


PROXY_PY_START_TIME = time.time()

# /path/to/proxy.py/proxy folder
PROXY_PY_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Path to virtualenv/lib/python3.X/site-packages
PROXY_PY_SITE_PACKAGES = sysconfig.get_path('purelib')
assert PROXY_PY_SITE_PACKAGES

CRLF = b'\r\n'
COLON = b':'
WHITESPACE = b' '
COMMA = b','
DOT = b'.'
SLASH = b'/'
AT = b'@'
HTTP_PROTO = b'http'
HTTPS_PROTO = HTTP_PROTO + b's'
HTTP_1_0 = HTTP_PROTO.upper() + SLASH + b'1.0'
HTTP_1_1 = HTTP_PROTO.upper() + SLASH + b'1.1'
HTTP_URL_PREFIX = HTTP_PROTO + COLON + SLASH + SLASH
HTTPS_URL_PREFIX = HTTPS_PROTO + COLON + SLASH + SLASH

LOCAL_INTERFACE_HOSTNAMES = (
    b'localhost',
    b'127.0.0.1',
    b'::1',
)

ANY_INTERFACE_HOSTNAMES = (
    b'0.0.0.0',
    b'::',
)

PROXY_AGENT_HEADER_KEY = b'Proxy-agent'
PROXY_AGENT_HEADER_VALUE = b'proxy.py v' + \
    __version__.encode('utf-8', 'strict')
PROXY_AGENT_HEADER = PROXY_AGENT_HEADER_KEY + \
    COLON + WHITESPACE + PROXY_AGENT_HEADER_VALUE

# Defaults
DEFAULT_BACKLOG = 100
DEFAULT_BASIC_AUTH = None
DEFAULT_MAX_SEND_SIZE = 64 * 1024
DEFAULT_BUFFER_SIZE = 128 * 1024
DEFAULT_CA_CERT_DIR = None
DEFAULT_CA_CERT_FILE = None
DEFAULT_CA_KEY_FILE = None
DEFAULT_CA_SIGNING_KEY_FILE = None
DEFAULT_CERT_FILE = None
DEFAULT_CA_FILE = pathlib.Path(
    PROXY_PY_SITE_PACKAGES,
) / 'certifi' / 'cacert.pem'
DEFAULT_CLIENT_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_DEVTOOLS_WS_PATH = b'/devtools'
DEFAULT_DISABLE_HEADERS: List[bytes] = []
DEFAULT_DISABLE_HTTP_PROXY = False
DEFAULT_ENABLE_DASHBOARD = False
DEFAULT_ENABLE_SSH_TUNNEL = False
DEFAULT_ENABLE_DEVTOOLS = False
DEFAULT_ENABLE_EVENTS = False
DEFAULT_EVENTS_QUEUE = None
DEFAULT_ENABLE_STATIC_SERVER = False
DEFAULT_ENABLE_WEB_SERVER = False
DEFAULT_ENABLE_REVERSE_PROXY = False
DEFAULT_ALLOWED_URL_SCHEMES = [HTTP_PROTO, HTTPS_PROTO]
DEFAULT_IPV4_HOSTNAME = ipaddress.IPv4Address('127.0.0.1')
DEFAULT_IPV6_HOSTNAME = ipaddress.IPv6Address('::1')
DEFAULT_KEY_FILE = None
DEFAULT_LOG_FILE = None
DEFAULT_LOG_FORMAT = '%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(module)s.%(funcName)s:%(lineno)d - %(message)s'
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_WEB_ACCESS_LOG_FORMAT = '{client_ip}:{client_port} - ' \
    '{request_method} {request_path} - {request_ua} - {connection_time_ms}ms'
DEFAULT_HTTP_PROXY_ACCESS_LOG_FORMAT = '{client_ip}:{client_port} - ' + \
    '{request_method} {server_host}:{server_port}{request_path} - ' + \
    '{response_code} {response_reason} - {response_bytes} bytes - ' + \
    '{connection_time_ms}ms'
DEFAULT_HTTPS_PROXY_ACCESS_LOG_FORMAT = '{client_ip}:{client_port} - ' + \
    '{request_method} {server_host}:{server_port} - ' + \
    '{response_bytes} bytes - {connection_time_ms}ms'
DEFAULT_REVERSE_PROXY_ACCESS_LOG_FORMAT = '{client_ip}:{client_port} - ' + \
    '{request_method} {request_path} -> {upstream_proxy_pass} - {connection_time_ms}ms'
DEFAULT_NUM_ACCEPTORS = 0
DEFAULT_NUM_WORKERS = 0
DEFAULT_OPEN_FILE_LIMIT = 1024
DEFAULT_PAC_FILE = None
DEFAULT_PAC_FILE_URL_PATH = b'/'
DEFAULT_PID_FILE = None
DEFAULT_PORT_FILE = None
DEFAULT_PLUGINS: List[Any] = []
DEFAULT_PORT = 8899
DEFAULT_SERVER_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_STATIC_SERVER_DIR = os.path.join(PROXY_PY_DIR, "public")
DEFAULT_MIN_COMPRESSION_LIMIT = 20  # In bytes
DEFAULT_THREADLESS = _env_threadless_compliant()
DEFAULT_LOCAL_EXECUTOR = True
DEFAULT_TIMEOUT = 10.0
DEFAULT_VERSION = False
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
DEFAULT_WORK_KLASS = 'proxy.http.HttpProtocolHandler'
DEFAULT_ENABLE_PROXY_PROTOCOL = False
# 25 milliseconds to keep the loops hot
# Will consume ~0.3-0.6% CPU when idle.
DEFAULT_SELECTOR_SELECT_TIMEOUT = 25 / 1000
DEFAULT_WAIT_FOR_TASKS_TIMEOUT = 1 / 1000
DEFAULT_INACTIVE_CONN_CLEANUP_TIMEOUT = 1   # in seconds

DEFAULT_DEVTOOLS_DOC_URL = 'http://proxy'
DEFAULT_DEVTOOLS_FRAME_ID = secrets.token_hex(8)
DEFAULT_DEVTOOLS_LOADER_ID = secrets.token_hex(8)

DEFAULT_DATA_DIRECTORY_PATH = os.path.join(str(pathlib.Path.home()), '.proxy')
DEFAULT_CACHE_DIRECTORY_PATH = os.path.join(
    DEFAULT_DATA_DIRECTORY_PATH, 'cache',
)
DEFAULT_CACHE_REQUESTS = False

# Cor plugins enabled by default or via flags
DEFAULT_ABC_PLUGINS = [
    'HttpProtocolHandlerPlugin',
    'HttpProxyBasePlugin',
    'HttpWebServerBasePlugin',
    'WebSocketTransportBasePlugin',
    'ReverseProxyBasePlugin',
]
PLUGIN_DASHBOARD = 'proxy.dashboard.ProxyDashboard'
PLUGIN_HTTP_PROXY = 'proxy.http.proxy.HttpProxyPlugin'
PLUGIN_PROXY_AUTH = 'proxy.http.proxy.auth.AuthPlugin'
PLUGIN_WEB_SERVER = 'proxy.http.server.HttpWebServerPlugin'
PLUGIN_REVERSE_PROXY = 'proxy.http.server.reverse.ReverseProxy'
PLUGIN_PAC_FILE = 'proxy.http.server.HttpWebServerPacFilePlugin'
PLUGIN_DEVTOOLS_PROTOCOL = 'proxy.http.inspector.devtools.DevtoolsProtocolPlugin'
PLUGIN_INSPECT_TRAFFIC = 'proxy.http.inspector.inspect_traffic.InspectTrafficPlugin'
PLUGIN_WEBSOCKET_TRANSPORT = 'proxy.http.websocket.transport.WebSocketTransport'

PY2_DEPRECATION_MESSAGE = '''DEPRECATION: proxy.py no longer supports Python 2.7.  Kindly upgrade to Python 3+. '
                'If for some reasons you cannot upgrade, use'
                '"pip install proxy.py==0.3".'''
