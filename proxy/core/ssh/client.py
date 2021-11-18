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
import socket
import ssl
from typing import Union

from ..connection import TcpClientConnection


class SshClient(TcpClientConnection):
    """Overrides TcpClientConnection.

    This is necessary because paramiko ``fileno()`` can be used for polling
    but not for send / recv.
    """

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        # Dummy return to comply with
        return socket.socket()
