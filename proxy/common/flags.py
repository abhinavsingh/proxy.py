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
import socket
import multiprocessing

from typing import Optional, Dict, List

from .types import IpAddress
from .constants import DEFAULT_BACKLOG, DEFAULT_BASIC_AUTH
from .constants import DEFAULT_TIMEOUT, DEFAULT_DEVTOOLS_WS_PATH, DEFAULT_DISABLE_HEADERS
from .constants import DEFAULT_ENABLE_STATIC_SERVER, DEFAULT_ENABLE_EVENTS
from .constants import DEFAULT_THREADLESS
from .constants import DEFAULT_PAC_FILE_URL_PATH, DEFAULT_PAC_FILE, DEFAULT_PID_FILE, DEFAULT_PORT
from .constants import DEFAULT_IPV6_HOSTNAME
from .constants import DEFAULT_SERVER_RECVBUF_SIZE, DEFAULT_CLIENT_RECVBUF_SIZE, DEFAULT_STATIC_SERVER_DIR
from .constants import DEFAULT_DATA_DIRECTORY_PATH


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
