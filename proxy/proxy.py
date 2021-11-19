# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       eventing
"""
import os
import sys
import time
import logging

from typing import List, Optional, Any

from .core.acceptor import AcceptorPool, ThreadlessPool, Listener
from .core.event import EventManager
from .common.utils import bytes_
from .common.flag import FlagParser, flags
from .common.constants import DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_LOG_LEVEL
from .common.constants import DEFAULT_OPEN_FILE_LIMIT, DEFAULT_PLUGINS, DEFAULT_VERSION
from .common.constants import DEFAULT_ENABLE_DASHBOARD, DEFAULT_WORK_KLASS, DEFAULT_PID_FILE


logger = logging.getLogger(__name__)


flags.add_argument(
    '--version',
    '-v',
    action='store_true',
    default=DEFAULT_VERSION,
    help='Prints proxy.py version.',
)

# TODO: Convert me into 1-letter choices
# TODO: Add --verbose option which also
# starts to log traffic flowing between
# clients and upstream servers.
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
    action='append',
    nargs='+',
    default=DEFAULT_PLUGINS,
    help='Comma separated plugins.  ' +
    'You may use --plugins flag multiple times.',
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

flags.add_argument(
    '--pid-file',
    type=str,
    default=DEFAULT_PID_FILE,
    help='Default: None. Save "parent" process ID to a file.',
)


class Proxy:
    """Context manager to control AcceptorPool, ExecutorPool & EventingCore lifecycle.

    By default, AcceptorPool is started with
    :class:`~proxy.http.handler.HttpProtocolHandler` work class.
    By definition, it expects HTTP traffic to flow between clients and server.

    Optionally, it also initializes the eventing core, a multi-process safe
    pubsub system queue which can be used to build various patterns
    for message sharing and/or signaling.
    """

    def __init__(self, input_args: Optional[List[str]] = None, **opts: Any) -> None:
        self.flags = FlagParser.initialize(input_args, **opts)
        self.listener: Optional[Listener] = None
        self.executors: Optional[ThreadlessPool] = None
        self.acceptors: Optional[AcceptorPool] = None
        self.event_manager: Optional[EventManager] = None

    def __enter__(self) -> 'Proxy':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

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
        self._write_pid_file()
        # We setup listeners first because of flags.port override
        # in case of ephemeral port being used
        self.listener = Listener(flags=self.flags)
        self.listener.setup()
        # Override flags.port to match the actual port
        # we are listening upon.  This is necessary to preserve
        # the server port when `--port=0` is used.
        self.flags.port = self.listener._port
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
            listener=self.listener,
            executor_queues=self.executors.work_queues,
            executor_pids=self.executors.work_pids,
            executor_locks=self.executors.work_locks,
            event_queue=event_queue,
        )
        self.acceptors.setup()
        # TODO: May be close listener fd as we don't need it now

    def shutdown(self) -> None:
        assert self.acceptors
        self.acceptors.shutdown()
        assert self.executors
        self.executors.shutdown()
        if self.flags.enable_events:
            assert self.event_manager is not None
            self.event_manager.shutdown()
        assert self.listener
        self.listener.shutdown()
        self._delete_pid_file()

    def _write_pid_file(self) -> None:
        if self.flags.pid_file is not None:
            # NOTE: Multiple instances of proxy.py running on
            # same host machine will currently result in overwriting the PID file
            with open(self.flags.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))

    def _delete_pid_file(self) -> None:
        if self.flags.pid_file and os.path.exists(self.flags.pid_file):
            os.remove(self.flags.pid_file)


def main(**opts: Any) -> None:
    try:
        with Proxy(sys.argv[1:], **opts):
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass


def entry_point() -> None:
    main()
