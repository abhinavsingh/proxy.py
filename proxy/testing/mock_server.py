from flask import Flask
from threading import Thread
import ctypes


class MockServer(Thread):
    def __init__(self, port):
        super().__init__()
        self.port = port
        self.app = Flask(__name__)
        self.url = "http://localhost:%s" % self.port

    def add_url_rule(self, url, callback, methods):
        self.app.add_url_rule(url, view_func=callback, methods=methods)

    def run(self):
        self.app.run(port=self.port)

    def shutdown_server(self):
        self.kill()
        self.join()

    def kill(self):
        thread_id = self.ident
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
            ctypes.c_long(thread_id), ctypes.py_object(SystemExit)
        )
        if res == 0:
            raise ValueError(f"Invalid thread id: {thread_id}")
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread_id), None)
            raise SystemExit("Stopping thread failure")
