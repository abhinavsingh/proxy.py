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
import argparse
import threading
import multiprocessing
from typing import Any

from proxy.core.work import (
    Work, ThreadlessPool, BaseLocalExecutor, BaseRemoteExecutor,
)
from proxy.core.event import eventNames
from proxy.common.flag import FlagParser
from proxy.common.backports import NonBlockingQueue


class Task:
    """This will be our work object."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        print(payload)


class TaskWork(Work[Task]):
    """This will be our handler class, created for each received work."""

    @staticmethod
    def create(*args: Any) -> Task:
        """Work core doesn't know how to create work objects for us, so
        we must provide an implementation of create method here."""
        return Task(*args)


class LocalTaskExecutor(BaseLocalExecutor):
    """We'll define a local executor which is capable of receiving
    log lines over a non blocking queue."""

    def work(self, *args: Any) -> None:
        task_id = int(time.time())
        uid = '%s-%s' % (self.iid, task_id)
        self.works[task_id] = self.flags.work_klass(
            self.flags.work_klass.create(*args),
            flags=self.flags,
            event_queue=self.event_queue,
            uid=uid,
            upstream_conn_pool=self._upstream_conn_pool,
        )
        self.works[task_id].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'uid': uid},
            publisher_id=self.__class__.__name__,
        )


class RemoteTaskExecutor(BaseRemoteExecutor):

    def work(self, *args: Any) -> None:
        no = int(time.time())
        uid = '%s-%s' % (self.iid, no)
        self.works[no] = self.flags.work_klass(
            self.flags.work_klass.create(*args),
            flags=self.flags,
            event_queue=self.event_queue,
            uid=uid,
            upstream_conn_pool=self._upstream_conn_pool,
        )
        self.works[no].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'uid': uid},
            publisher_id=self.__class__.__name__,
        )


def start_local(flags: argparse.Namespace) -> None:
    work_queue = NonBlockingQueue()
    executor = LocalTaskExecutor(iid=1, work_queue=work_queue, flags=flags)

    t = threading.Thread(target=executor.run)
    t.daemon = True
    t.start()

    try:
        i = 0
        while True:
            work_queue.put(('%d' % i).encode('utf-8'))
            i += 1
    except KeyboardInterrupt:
        pass
    finally:
        executor.running.set()
        t.join()


def start_remote(flags: argparse.Namespace) -> None:
    pipe = multiprocessing.Pipe()
    work_queue = pipe[0]
    executor = RemoteTaskExecutor(iid=1, work_queue=pipe[1], flags=flags)

    p = multiprocessing.Process(target=executor.run)
    p.daemon = True
    p.start()

    try:
        i = 0
        while True:
            work_queue.send(('%d' % i).encode('utf-8'))
            i += 1
    except KeyboardInterrupt:
        pass
    finally:
        executor.running.set()
        p.join()


def start_remote_pool(flags: argparse.Namespace) -> None:
    with ThreadlessPool(flags=flags, executor_klass=RemoteTaskExecutor) as pool:
        try:
            i = 0
            while True:
                work_queue = pool.work_queues[i % flags.num_workers]
                work_queue.send(('%d' % i).encode('utf-8'))
                i += 1
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    flags = FlagParser.initialize(
        ['--disable-http-proxy'],
        work_klass=TaskWork,
    )
    start_remote_pool(flags)
    # start_remote(flags)
    # start_local(flags)
