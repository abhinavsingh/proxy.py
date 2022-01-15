# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import sys
import time
import signal
import logging

from typing import List, Optional, Any

from proxy.core.ssh.listener import SshTunnelListener

from .core.work import ThreadlessPool
from .core.event import EventManager
from .core.ssh import SshHttpProtocolHandler
from .core.acceptor import AcceptorPool, Listener

from .common.utils import bytes_
from .common.flag import FlagParser, flags
from .common.constants import DEFAULT_ENABLE_SSH_TUNNEL, DEFAULT_LOCAL_EXECUTOR, DEFAULT_LOG_FILE
from .common.constants import DEFAULT_OPEN_FILE_LIMIT, DEFAULT_PLUGINS, DEFAULT_VERSION
from .common.constants import DEFAULT_ENABLE_DASHBOARD, DEFAULT_WORK_KLASS, DEFAULT_PID_FILE
from .common.constants import DEFAULT_LOG_FORMAT, DEFAULT_LOG_LEVEL, IS_WINDOWS


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
    '--enable-ssh-tunnel',
    action='store_true',
    default=DEFAULT_ENABLE_SSH_TUNNEL,
    help='Default: False.  Enable SSH tunnel.',
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
    """Proxy is a context manager to control proxy.py library core.

    By default, :class:`~proxy.core.pool.AcceptorPool` is started with
    :class:`~proxy.http.handler.HttpProtocolHandler` work class.
    By definition, it expects HTTP traffic to flow between clients and server.

    In ``--threadless`` mode and without ``--local-executor``,
    a :class:`~proxy.core.executors.ThreadlessPool` is also started.
    Executor pool receives newly accepted work by :class:`~proxy.core.acceptor.Acceptor`
    and creates an instance of work class for processing the received work.

    Optionally, Proxy class also initializes the EventManager.
    A multi-process safe pubsub system which can be used to build various
    patterns for message sharing and/or signaling.
    """

    def __init__(self, input_args: Optional[List[str]] = None, **opts: Any) -> None:
        self.flags = FlagParser.initialize(input_args, **opts)
        self.listener: Optional[Listener] = None
        self.executors: Optional[ThreadlessPool] = None
        self.acceptors: Optional[AcceptorPool] = None
        self.event_manager: Optional[EventManager] = None
        self.ssh_http_protocol_handler: Optional[SshHttpProtocolHandler] = None
        self.ssh_tunnel_listener: Optional[SshTunnelListener] = None

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
        self._write_port_file()
        # Setup EventManager
        if self.flags.enable_events:
            logger.info('Core Event enabled')
            self.event_manager = EventManager()
            self.event_manager.setup()
        event_queue = self.event_manager.queue \
            if self.event_manager is not None \
            else None
        # Setup remote executors only if
        # --local-executor mode isn't enabled.
        if self.remote_executors_enabled:
            self.executors = ThreadlessPool(
                flags=self.flags,
                event_queue=event_queue,
            )
            self.executors.setup()
        # Setup acceptors
        self.acceptors = AcceptorPool(
            flags=self.flags,
            listener=self.listener,
            executor_queues=self.executors.work_queues if self.executors else [],
            executor_pids=self.executors.work_pids if self.executors else [],
            executor_locks=self.executors.work_locks if self.executors else [],
            event_queue=event_queue,
        )
        self.acceptors.setup()
        # Start SSH tunnel acceptor if enabled
        if self.flags.enable_ssh_tunnel:
            self.ssh_http_protocol_handler = SshHttpProtocolHandler(
                flags=self.flags,
            )
            self.ssh_tunnel_listener = SshTunnelListener(
                flags=self.flags,
                on_connection_callback=self.ssh_http_protocol_handler.on_connection,
            )
            self.ssh_tunnel_listener.setup()
            self.ssh_tunnel_listener.start_port_forward(
                ('', self.flags.tunnel_remote_port),
            )
        # TODO: May be close listener fd as we don't need it now
        self._register_signals()

    def shutdown(self) -> None:
        if self.flags.enable_ssh_tunnel:
            assert self.ssh_tunnel_listener is not None
            self.ssh_tunnel_listener.shutdown()
        assert self.acceptors
        self.acceptors.shutdown()
        if self.remote_executors_enabled:
            assert self.executors
            self.executors.shutdown()
        if self.flags.enable_events:
            assert self.event_manager is not None
            self.event_manager.shutdown()
        assert self.listener
        self.listener.shutdown()
        self._delete_port_file()
        self._delete_pid_file()

    @property
    def remote_executors_enabled(self) -> bool:
        return self.flags.threadless and \
            not (self.flags.local_executor == int(DEFAULT_LOCAL_EXECUTOR))

    def _write_pid_file(self) -> None:
        if self.flags.pid_file:
            with open(self.flags.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))

    def _delete_pid_file(self) -> None:
        if self.flags.pid_file \
                and os.path.exists(self.flags.pid_file):
            os.remove(self.flags.pid_file)

    def _write_port_file(self) -> None:
        if self.flags.port_file:
            with open(self.flags.port_file, 'wb') as port_file:
                port_file.write(bytes_(self.flags.port))

    def _delete_port_file(self) -> None:
        if self.flags.port_file \
                and os.path.exists(self.flags.port_file):
            os.remove(self.flags.port_file)

    def _register_signals(self) -> None:
        # TODO: Handle SIGINFO, SIGUSR1, SIGUSR2
        signal.signal(signal.SIGINT, self._handle_exit_signal)
        signal.signal(signal.SIGTERM, self._handle_exit_signal)
        if not IS_WINDOWS:
            signal.signal(signal.SIGHUP, self._handle_exit_signal)
            # TODO: SIGQUIT is ideally meant to terminate with core dumps
            signal.signal(signal.SIGQUIT, self._handle_exit_signal)

    @staticmethod
    def _handle_exit_signal(signum: int, _frame: Any) -> None:
        logger.info('Received signal %d' % signum)
        sys.exit(0)


def sleep_loop() -> None:
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break


def main(**opts: Any) -> None:
    with Proxy(sys.argv[1:], **opts):
        sleep_loop()


def entry_point() -> None:
    main()
