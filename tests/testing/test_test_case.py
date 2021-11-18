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
import unittest
import proxy

from proxy.common.utils import get_available_port


class TestTestCase(unittest.TestCase):

    def test_wait_for_server_raises_timeout_error(self) -> None:
        with self.assertRaises(TimeoutError):
            proxy.TestCase.wait_for_server(
                get_available_port(), wait_for_seconds=0.1,
            )
