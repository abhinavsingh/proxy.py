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
import logging

from proxy.http.websocket import (
    WebsocketFrame, WebsocketClient, websocketOpcodes,
)
from proxy.common.constants import DEFAULT_LOG_FORMAT

logging.basicConfig(level=logging.INFO, format=DEFAULT_LOG_FORMAT)

# globals
client: WebsocketClient
last_dispatch_time: float
static_frame = memoryview(WebsocketFrame.text(b'hello'))
num_echos = 10

logger = logging.getLogger(__name__)


def on_message(frame: WebsocketFrame) -> None:
    """WebsocketClient on_message callback."""
    global client, num_echos, last_dispatch_time
    logger.info(
        'Received %r after %d millisec' %
        (frame.data, (time.time() - last_dispatch_time) * 1000),
    )
    assert(
        frame.data == b'hello' and frame.opcode ==
        websocketOpcodes.TEXT_FRAME
    )
    if num_echos > 0:
        client.queue(static_frame)
        last_dispatch_time = time.time()
        num_echos -= 1
    else:
        client.close()


if __name__ == '__main__':
    # Constructor establishes socket connection
    client = WebsocketClient(
        b'localhost',
        8899,
        b'/ws-route-example',
        on_message=on_message,
    )
    # Perform handshake
    client.handshake()
    # Queue some data for client
    client.queue(static_frame)
    last_dispatch_time = time.time()
    # Start event loop
    client.run()
