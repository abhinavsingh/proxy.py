# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from aiohttp import web


async def handle(request: web.Request) -> web.StreamResponse:
    return web.Response(body=b'HTTP route response')


app = web.Application()

app.add_routes(
    [
        web.get('/http-route-example', handle),
    ],
)

web.run_app(app, host='127.0.0.1', port=8080)
