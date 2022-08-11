from flask import Flask
from werkzeug.serving import make_server
from threading import Thread
import ctypes


class MockServer(Thread):
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.app = Flask(__name__)
        self.url = "http://localhost:%s" % self.port
        self.server = make_server('localhost', self.port, self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()

    def add_url_rule(self, url, callback, methods):
        self.app.add_url_rule(url, view_func=callback, methods=methods)

    def run(self):
        self.server.serve_forever()

    def shutdown_server(self):
        self.server.shutdown()
