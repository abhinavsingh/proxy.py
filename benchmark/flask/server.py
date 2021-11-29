# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from flask import Flask

app = Flask(__name__)


@app.route('/http-route-example')
def hello_world():
    return b'HTTP route response'


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)
