# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
import logging

from proxy.core.connection import TcpServerConnection
from proxy.common.constants import DEFAULT_BUFFER_SIZE

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    client = TcpServerConnection('::', 12345)
    client.connect()
    client.wrap('example.com', ca_file='ca-cert.pem')
    # wrap() will by default set connection to nonblocking
    # flip it back to blocking
    client.connection.setblocking(True)
    try:
        while True:
            client.send(b'hello')
            data = client.recv(DEFAULT_BUFFER_SIZE)
            if data is None:
                break
            logger.info(data.tobytes())
    finally:
        client.close()
