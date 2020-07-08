# Proxy Library Examples

This directory contains examples that demonstrate `proxy.py` core library capabilities.

Looking for `proxy.py` plugin examples?  Check [proxy/plugin](https://github.com/abhinavsingh/proxy.py/tree/develop/proxy/plugin) directory.

## WebSocket Client

1. Makes use of `proxy.http.websocket.WebsocketClient` which is built on-top of `asyncio`
2. `websocket_client.py` by default opens a WebSocket connection to `ws://echo.websocket.org`.
3. Client will exchange `num_echos = 10` packets with the server and then shutdown.

Start `websocket_client.py` as:

```bash
❯ PYTHONPATH=. python examples/websocket_client.py
Received b'hello' after 306 millisec
Received b'hello' after 308 millisec
Received b'hello' after 277 millisec
Received b'hello' after 334 millisec
Received b'hello' after 296 millisec
Received b'hello' after 317 millisec
Received b'hello' after 307 millisec
Received b'hello' after 307 millisec
Received b'hello' after 306 millisec
Received b'hello' after 307 millisec
Received b'hello' after 309 millisec
```

## TCP Echo Server

1. Makes use of `proxy.core.acceptor.AcceptorPool`, same multicore acceptor used internally by `proxy.py` server.
2. Implements `proxy.core.acceptor.Work` interface to handle incoming client connections.

Start `tcp_echo_server.py` as:

```bash
❯ PYTHONPATH=. python examples/tcp_echo_server.py
Connection accepted from ('::1', 53285, 0, 0)
Connection closed by client ('::1', 53285, 0, 0)
```

## TCP Echo Client

1. Makes use of `proxy.common.utils.socket_connection` to establish a TCP socket connection with our TCP echo server.
2. Exchanges packet with server in an infinite loop.  Press `CTRL+C` to stop.

Start `tcp_echo_client.py` as:

```bash
❯ PYTHONPATH=. python examples/tcp_echo_client.py
b'hello'
b'hello'
b'hello'
b'hello'
b'hello'
...
...
...
^CTraceback (most recent call last):
  File "examples/tcp_echo_client.py", line 18, in <module>
    data = client.recv(DEFAULT_BUFFER_SIZE)
KeyboardInterrupt
```

## SSL Echo Server

1. Same as `tcp_echo_server.py`.
2. Internally uses `proxy.common.utils.wrap_socket` to enable SSL encryption.
3. Uses `https-key.pem` and `https-signed-cert.pem` for SSL encryption.

Start `ssl_echo_server.py` as:

```bash
❯ PYTHONPATH=. python examples/ssl_echo_server.py
```

## SSL Echo Client

1. Makes use of `proxy.core.connection.TcpServerConnection` to establish a SSL connection with our `ssl_echo_server.py`.
2. Uses generated `ca-cert.pem` for SSL certificate verification.

Start `ssl_echo_client.py` as:

```bash
❯ PYTHONPATH=. python examples/ssl_echo_client.py
```
