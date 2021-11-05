# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging

from proxy.common.constants import DEFAULT_BUFFER_SIZE
from proxy.common.utils import socket_connection


logger = logging.getLogger(__name__)

if __name__ == '__main__':
    with socket_connection(('::', 12345)) as client:
        while True:
            client.send(b'hello')
            data = client.recv(DEFAULT_BUFFER_SIZE)
            if data is None:
                break
            logger.info(data)
