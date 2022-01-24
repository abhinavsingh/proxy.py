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

    def run(self) -> None:
        self.executor.run()
