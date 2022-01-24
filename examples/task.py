# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import argparse

from proxy.core.work import ThreadlessPool
from proxy.common.flag import FlagParser
from proxy.core.work.task import (
    RemoteTaskExecutor, ThreadedTaskExecutor, SingleProcessTaskExecutor,
)


def start_local(flags: argparse.Namespace) -> None:
    thread = ThreadedTaskExecutor(flags=flags)
    thread.start()
    try:
        i = 0
        while True:
            thread.executor.work_queue.put(('%d' % i).encode('utf-8'))
            i += 1
    except KeyboardInterrupt:
        pass
    finally:
        thread.executor.running.set()
        thread.join()


def start_remote(flags: argparse.Namespace) -> None:
    process = SingleProcessTaskExecutor(flags=flags)
    process.start()

    try:
        i = 0
        while True:
            process.work_queue.send(('%d' % i).encode('utf-8'))
            i += 1
    except KeyboardInterrupt:
        pass
    finally:
        process.executor.running.set()
        process.join()


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


# TODO: TaskWork, LocalTaskExecutor, RemoteTaskExecutor
# should not be needed, abstract those pieces out in the core
# for stateless tasks.
if __name__ == '__main__':
    flags = FlagParser.initialize(
        ['--disable-http-proxy'],
        work_klass='proxy.core.work.task.TaskHandler',
    )
    start_remote_pool(flags)
    # start_remote(flags)
    # start_local(flags)
