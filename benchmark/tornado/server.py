# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import tornado.ioloop
import tornado.web


class MainHandler(tornado.web.RequestHandler):      # type: ignore
    def get(self) -> None:
        self.write('HTTP route response')


def make_app() -> tornado.web.Application:
    return tornado.web.Application([
        (r'/http-route-example', MainHandler),
    ])


if __name__ == '__main__':
    app = make_app()
    app.listen(8888, address='127.0.0.1')
    tornado.ioloop.IOLoop.current().start()
