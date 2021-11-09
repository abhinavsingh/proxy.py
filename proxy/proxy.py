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
import time
import logging

from typing import List, Optional, Any, Type

from .core.acceptor import AcceptorPool, ThreadlessPool, Work
from .core.event import EventManager
from .http import HttpProtocolHandler
from .common.flag import FlagParser, flags
from .common.constants import DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_LOG_LEVEL
from .common.constants import DEFAULT_OPEN_FILE_LIMIT, DEFAULT_PLUGINS, DEFAULT_VERSION
from .common.constants import DEFAULT_ENABLE_DASHBOARD, DEFAULT_WORK_KLASS
from .common.context_managers import SetupShutdownContextManager


logger = logging.getLogger(__name__)


flags.add_argument(
    '--version',
    '-v',
    action='store_true',
    default=DEFAULT_VERSION,
    help='Prints proxy.py version.',
)

flags.add_argument(
    '--log-level',
    type=str,
    default=DEFAULT_LOG_LEVEL,
    help='Valid options: DEBUG, INFO (default), WARNING, ERROR, CRITICAL. '
    'Both upper and lowercase values are allowed. '
    'You may also simply use the leading character e.g. --log-level d',
)

flags.add_argument(
    '--log-file',
    type=str,
    default=DEFAULT_LOG_FILE,
    help='Default: sys.stdout. Log file destination.',
)

flags.add_argument(
    '--log-format',
    type=str,
    default=DEFAULT_LOG_FORMAT,
    help='Log format for Python logger.',
)

flags.add_argument(
    '--open-file-limit',
    type=int,
    default=DEFAULT_OPEN_FILE_LIMIT,
    help='Default: 1024. Maximum number of files (TCP connections) '
    'that proxy.py can open concurrently.',
)

flags.add_argument(
    '--plugins',
    type=str,
    default=DEFAULT_PLUGINS,
    help='Comma separated plugins',
)

# TODO: Ideally all `--enable-*` flags must be at the top-level.
# --enable-dashboard is specially needed here because
# ProxyDashboard class is not imported anywhere.
#
# Due to which, if we move this flag definition within dashboard
# plugin, users will have to explicitly enable dashboard plugin
# to also use flags provided by it.
flags.add_argument(
    '--enable-dashboard',
    action='store_true',
    default=DEFAULT_ENABLE_DASHBOARD,
    help='Default: False.  Enables proxy.py dashboard.',
)

flags.add_argument(
    '--work-klass',
    type=str,
    default=DEFAULT_WORK_KLASS,
    help='Default: ' + DEFAULT_WORK_KLASS +
    '.  Work klass to use for work execution.',
)


class Proxy(SetupShutdownContextManager):
    """Context manager to control AcceptorPool, ExecutorPool & EventingCore lifecycle.

    By default, AcceptorPool is started with `HttpProtocolHandler` work class.
    By definition, it expects HTTP traffic to flow between clients and server.

    Optionally, it also initializes the eventing core, a multi-process safe
    pubsub system queue which can be used to build various patterns
    for message sharing and/or signaling.
    """

    def __init__(self, **opts: Any) -> None:
        input_args = sys.argv[1:]
        print(input_args)
        print('*'*20)
        self.flags = FlagParser.initialize(input_args, **opts)
        print(self.flags)
        self.acceptors: Optional[AcceptorPool] = None
        self.executors: Optional[ThreadlessPool] = None
        self.event_manager: Optional[EventManager] = None

    def setup(self) -> None:
        # TODO: Introduce cron feature
        # https://github.com/abhinavsingh/proxy.py/issues/392
        #
        # TODO: Introduce ability to publish
        # adhoc events which can modify behaviour of server
        # at runtime.  Example, updating flags, plugin
        # configuration etc.
        #
        # TODO: Python shell within running proxy.py environment?
        #
        # TODO: Pid watcher which watches for processes started
        # by proxy.py core.  May be alert or restart those processes
        # on failure.
        if self.flags.enable_events:
            logger.info('Core Event enabled')
            self.event_manager = EventManager()
            self.event_manager.setup()
        event_queue = self.event_manager.queue \
            if self.event_manager is not None \
            else None
        self.executors = ThreadlessPool(
            flags=self.flags,
            event_queue=event_queue,
        )
        self.executors.setup()
        self.acceptors = AcceptorPool(
            flags=self.flags,
            event_queue=event_queue,
            executor_queues=self.executors.work_queues,
            executor_pids=self.executors.work_pids,
        )
        self.acceptors.setup()
        assert self.acceptors is not None
        if self.flags.unix_socket_path:
            logger.info(
                'Listening on %s' %
                self.flags.unix_socket_path,
            )
        else:
            logger.info(
                'Listening on %s:%s' %
                (self.acceptors.flags.hostname, self.acceptors.flags.port),
            )

    def shutdown(self) -> None:
        assert self.acceptors
        self.acceptors.shutdown()
        assert self.executors
        self.executors.shutdown()
        if self.flags.enable_events:
            assert self.event_manager is not None
            self.event_manager.shutdown()


def main(**opts: Any) -> None:
    try:
        with Proxy(**opts):
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


def entry_point() -> None:
    main()
