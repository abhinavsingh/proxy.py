# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import uvicorn

from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route


async def homepage(request):
    return Response('HTTP route response', media_type='text/plain')


app = Starlette(debug=True, routes=[
    Route('/http-route-example', homepage),
])


if __name__ == '__main__':
    uvicorn.run("server:app", port=8890, workers=10, log_level="warning")
