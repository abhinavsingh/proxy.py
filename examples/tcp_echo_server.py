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
import time
from typing import Optional

from proxy import Proxy
from proxy.core.base import BaseTcpServerHandler


class EchoServerHandler(BaseTcpServerHandler):
    """Sets client socket to non-blocking during initialization."""

    def initialize(self) -> None:
        self.work.connection.setblocking(False)

    def handle_data(self, data: memoryview) -> Optional[bool]:
        # echo back to client
        self.work.queue(data)
        return None


def main() -> None:
    # This example requires `threadless=True`
    with Proxy(
        work_klass=EchoServerHandler,
        threadless=True,
        num_workers=1,
        port=12345,
    ):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
