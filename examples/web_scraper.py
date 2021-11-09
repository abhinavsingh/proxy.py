# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time
import socket

from typing import Dict

from proxy import Proxy
from proxy.core.acceptor import Work
from proxy.common.types import Readables, Writables


class WebScraper(Work):
    """Demonstrates how to orchestrate a generic work acceptors and executors
    workflow using proxy.py core.

    By default, `WebScraper` expects to receive work from a file on disk.
    Each line in the file must be a URL to scrape.  Received URL is scrapped
    by the implementation in this class.

    After scrapping, results are published to the eventing core.  One or several
    result subscriber can then handle the result as necessary.  Currently, result
    subscribers consume the scrapped response and write discovered URL in the
    file on the disk.  This creates a feedback loop.  Allowing WebScraper to
    continue endlessly.

    NOTE: No loop detection is performed currently.

    NOTE: File descriptor need not point to a file on disk.
    Example, file descriptor can be a database connection.
    For simplicity, imagine a Redis server connection handling
    only PUBSUB protocol.
    """

    def get_events(self) -> Dict[socket.socket, int]:
        """Return sockets and events (read or write) that we are interested in."""
        return {}

    def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        """Handle readable and writable sockets.

        Return True to shutdown work."""
        return False


if __name__ == '__main__':
    with Proxy(
        work_klass=WebScraper,
        threadless=True,
        num_workers=1,
        port=12345,
    ) as pool:
        while True:
            time.sleep(1)
