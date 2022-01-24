# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import sys
import argparse

from proxy.core.work import ThreadlessPool
from proxy.common.flag import FlagParser
from proxy.core.work.task import (
    RemoteTaskExecutor, ThreadedTaskExecutor, SingleProcessTaskExecutor,
)


def start_local_thread(flags: argparse.Namespace) -> None:
    with ThreadedTaskExecutor(flags=flags) as thread:
        i = 0
        while True:
            thread.executor.work_queue.put(('%d' % i).encode('utf-8'))
            i += 1


def start_remote_process(flags: argparse.Namespace) -> None:
    with SingleProcessTaskExecutor(flags=flags) as process:
        i = 0
        while True:
            process.work_queue.send(('%d' % i).encode('utf-8'))
            i += 1


def start_remote_pool(flags: argparse.Namespace) -> None:
    with ThreadlessPool(flags=flags, executor_klass=RemoteTaskExecutor) as pool:
        i = 0
        while True:
            work_queue = pool.work_queues[i % flags.num_workers]
            work_queue.send(('%d' % i).encode('utf-8'))
            i += 1


def main() -> None:
    try:
        flags = FlagParser.initialize(
            sys.argv[2:] + ['--disable-http-proxy'],
            work_klass='proxy.core.work.task.TaskHandler',
        )
        globals()['start_%s' % sys.argv[1]](flags)
    except KeyboardInterrupt:
        pass


# TODO: TaskWork, LocalTaskExecutor, RemoteTaskExecutor
# should not be needed, abstract those pieces out in the core
# for stateless tasks.
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(
            '\n'.join([
                'Usage:',
                '  %s <execution-mode>' % sys.argv[0],
                '    execution-mode can be one of the following:',
                '    "remote_pool", "remote_process", "local_thread"',
            ])
        )
        sys.exit(1)
    main()
