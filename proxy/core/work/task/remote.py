# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time
import uuid
import multiprocessing
from typing import Any

from ..remote import BaseRemoteExecutor


class RemoteTaskExecutor(BaseRemoteExecutor):

    def work(self, *args: Any) -> None:
        task_id = int(time.time())
        uid = '%s-%s' % (self.iid, task_id)
        self.works[task_id] = self.create(uid, *args)


class SingleProcessTaskExecutor(multiprocessing.Process):

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        self.daemon = True
        self.work_queue, remote = multiprocessing.Pipe()
        self.executor = RemoteTaskExecutor(
            iid=uuid.uuid4().hex,
            work_queue=remote,
            **kwargs,
        )

    def __enter__(self) -> 'SingleProcessTaskExecutor':
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.executor.running.set()
        self.join()

    def run(self) -> None:
        self.executor.run()
