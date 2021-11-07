# Proxy Library Examples

This directory contains examples that demonstrate `proxy.py` core library capabilities.

Looking for `proxy.py` plugin examples?  Check [proxy/plugin](https://github.com/abhinavsingh/proxy.py/tree/develop/proxy/plugin) directory.

Table of Contents
=================
* [Generic Work Acceptor and Executor](#generic-work-acceptor-and-executor)
* [WebSocket Client](#websocket-client)
* [TCP Echo Server](#tcp-echo-server)
* [TCP Echo Client](#tcp-echo-client)
* [SSL Echo Server](#ssl-echo-server)
* [SSL Echo Client](#ssl-echo-client)
* [PubSub Eventing](#pubsub-eventing)
* [Https Connect Tunnel](#https-connect-tunnel)

## Generic Work Acceptor and Executor

1. Makes use of `proxy.core.AcceptorPool` and `proxy.core.Work`
2. Demonstrates how to perform generic work using `proxy.py` core.

Start `web_scraper.py` as:

```console
❯ PYTHONPATH=. python examples/web_scraper.py
```

## WebSocket Client

1. Makes use of `proxy.http.websocket.WebsocketClient` which is built on-top of `asyncio`
2. `websocket_client.py` by default opens a WebSocket connection to `ws://echo.websocket.org`.
3. Client will exchange `num_echos = 10` packets with the server and then shutdown.

Start `websocket_client.py` as:

```console
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

```console
❯ PYTHONPATH=. python examples/tcp_echo_server.py
Connection accepted from ('::1', 53285, 0, 0)
Connection closed by client ('::1', 53285, 0, 0)
```

## TCP Echo Client

1. Makes use of `proxy.common.utils.socket_connection` to establish a TCP socket connection with our TCP echo server.
2. Exchanges packet with server in an infinite loop.  Press `CTRL+C` to stop.

Start `tcp_echo_client.py` as:

```console
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
3. Uses `https-key.pem` and `https-signed-cert.pem` for SSL encryption.  See [End-to-End Encryption](https://github.com/abhinavsingh/proxy.py#end-to-end-encryption) for instructions on how to generate SSL certificates.

Start `ssl_echo_server.py` as:

```console
❯ PYTHONPATH=. python examples/ssl_echo_server.py
```

## SSL Echo Client

1. Makes use of `proxy.core.connection.TcpServerConnection` to establish a SSL connection with our `ssl_echo_server.py`.
2. Uses generated `ca-cert.pem` for SSL certificate verification.

Start `ssl_echo_client.py` as:

```console
❯ PYTHONPATH=. python examples/ssl_echo_client.py
```

## PubSub Eventing

1. Makes use of `proxy.py` core eventing module.
2. A `proxy.core.event.EventDispatcher` thread is started.
3. A `proxy.core.event.EventSubscriber` thread is started.
4. A `multiprocessing.Process` publisher is started.
5. Main thread also publishes into `EventDispatcher` queue.
6. Events from both the main thread and another process are received by the subscriber.

Start `pubsub_eventing.py` as:

```console
❯ PYTHONPATH=. python examples/pubsub_eventing.py
DEBUG:proxy.core.event.subscriber:Subscribed relay sub id 5eb22010764f4d44900f41e2fb408ca6 from core events
publisher starting
^Cpublisher shutdown
bye!!!
DEBUG:proxy.core.event.subscriber:Un-subscribed relay sub id 5eb22010764f4d44900f41e2fb408ca6 from core events
Received 52724 events from main thread, 60172 events from another process, in 21.50117802619934 seconds
```

## HTTPS Connect Tunnel

A simple HTTP proxy server supporting only CONNECT (https) requests.

1. Uses `HttpParser` for request parsing.
2. Uses `TcpServerConnection` to establish upstream connection.
3. Overrides `BaseServer` methods to also register read/write events for upstream connection.

Start `https_connect_tunnel.py` as:

```
❯ PYTHONPATH=. python examples/https_connect_tunnel.py
```

Send https requests via tunnel as:

```
❯ curl -x localhost:12345 https://httpbin.org/get
```
