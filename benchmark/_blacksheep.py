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
# from blacksheep.server import Application
# from blacksheep.server.responses import text


# app = Application()


# @app.route('/http-route-example')
async def home(request):    # type: ignore[no-untyped-def]
    # return text('HTTP route response')
    pass

if __name__ == '__main__':
    uvicorn.run('server:app', port=9000, workers=10, log_level='warning')
