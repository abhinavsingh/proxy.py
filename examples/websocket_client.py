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
from proxy.http.websocket import WebsocketClient, WebsocketFrame, websocketOpcodes


# globals
client: WebsocketClient
last_dispatch_time: float
static_frame = memoryview(WebsocketFrame.text(b'hello'))
num_echos = 10


def on_message(frame: WebsocketFrame) -> None:
    """WebsocketClient on_message callback."""
    global client, num_echos, last_dispatch_time
    print(
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
        b'echo.websocket.org',
        80,
        b'/',
        on_message=on_message,
    )
    # Perform handshake
    client.handshake()
    # Queue some data for client
    client.queue(static_frame)
    last_dispatch_time = time.time()
    # Start event loop
    client.run()
