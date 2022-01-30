# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import ssl
import logging

from proxy.core.connection import TcpServerConnection
from proxy.common.constants import DEFAULT_BUFFER_SIZE, DEFAULT_LOG_FORMAT

logging.basicConfig(level=logging.INFO, format=DEFAULT_LOG_FORMAT)

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    client = TcpServerConnection('127.0.0.1', 12345)
    client.connect()
    client.wrap(
        None,  # 'localhost',
        ca_file='ca-cert.pem',
        verify_mode=ssl.CERT_NONE,
    )
    try:
        while True:
            client.send(b'hello')
            data = client.recv(DEFAULT_BUFFER_SIZE)
            if data is None:
                break
            logger.info(data.tobytes())
    finally:
        client.close()
