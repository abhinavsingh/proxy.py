import requests

from flask import Flask, request
from threading import Thread

class MockServer(Thread):
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.app = Flask(__name__)
        self.url = "http://localhost:%s" % self.port
        self.app.add_url_rule("/shutdown", view_func=self._shutdown_server)

    def add_url_rule(self, url, callback, methods):
        self.app.add_url_rule(url, view_func=callback, methods=methods)

    def _shutdown_server(self):
        if not 'werkzeug.server.shutdown' in request.environ:
            raise RuntimeError('Not running the development server')
        request.environ['werkzeug.server.shutdown']()
        return 'Server shutting down...'

    def run(self):
        self.app.run(port=self.port)

    def shutdown_server(self):
        requests.get("http://localhost:%s/shutdown" % self.port)
        self.join()
