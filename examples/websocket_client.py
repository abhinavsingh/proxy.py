# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from proxy.http.websocket import WebsocketClient, WebsocketFrame, websocketOpcodes


client: WebsocketClient
static_frame = memoryview(WebsocketFrame.text(b'hello'))


def on_message(frame: WebsocketFrame) -> None:
    """WebsocketClient on_message callback."""
    global client
    print(frame.data)
    assert(frame.data == b'hello')
    assert(frame.opcode == websocketOpcodes.TEXT_FRAME)
    client.queue(static_frame)


if __name__ == '__main__':
    # Constructor establishes socket connection
    client = WebsocketClient(b'echo.websocket.org', 80, b'/', on_message=on_message)
    # Perform handshake
    client.handshake()
    # Queue some data for client
    client.queue(static_frame)
    # Start event loop
    client.run()
