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
import socket
import logging
import argparse
from typing import TYPE_CHECKING, Any, Set, Optional, cast


try:
    if TYPE_CHECKING:  # pragma: no cover
        from ...common.types import HostPort
except ImportError:     # pragma: no cover
    pass

from .base import BaseSshTunnelHandler, BaseSshTunnelListener
from ...common.flag import flags


logger = logging.getLogger(__name__)


flags.add_argument(
    '--tunnel-hostname',
    type=str,
    default=None,
    help='Default: None. Remote hostname or IP address to which SSH tunnel will be established.',
)

flags.add_argument(
    '--tunnel-port',
    type=int,
    default=22,
    help='Default: 22. SSH port of the remote host.',
)

flags.add_argument(
    '--tunnel-username',
    type=str,
    default=None,
    help='Default: None. Username to use for establishing SSH tunnel.',
)

flags.add_argument(
    '--tunnel-ssh-key',
    type=str,
    default=None,
    help='Default: None. Private key path in pem format',
)

flags.add_argument(
    '--tunnel-ssh-key-passphrase',
    type=str,
    default=None,
    help='Default: None. Private key passphrase',
)

flags.add_argument(
    '--tunnel-remote-port',
    type=int,
    default=8899,
    help='Default: 8899. Remote port which will be forwarded locally for proxy.',
)


class SshTunnelListener(BaseSshTunnelListener):
    """Connects over SSH and forwards a remote port to local host.

    Incoming connections are delegated to provided callback."""

    def __init__(
        self,
        flags: argparse.Namespace,
        handler: BaseSshTunnelHandler,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        paramiko_logger = logging.getLogger('paramiko')
        paramiko_logger.setLevel(logging.WARNING)

        # pylint: disable=import-outside-toplevel
        from paramiko import SSHClient
        from paramiko.transport import Transport

        self.flags = flags
        self.handler = handler
        self.ssh: Optional[SSHClient] = None
        self.transport: Optional[Transport] = None
        self.forwarded: Set['HostPort'] = set()

    def start_port_forward(self, remote_addr: 'HostPort') -> None:
        assert self.transport is not None
        self.transport.request_port_forward(
            *remote_addr,
            handler=self.handler.on_connection,
        )
        self.forwarded.add(remote_addr)
        logger.debug("%s:%d forwarding successful..." % remote_addr)

    def stop_port_forward(self, remote_addr: 'HostPort') -> None:
        assert self.transport is not None
        self.transport.cancel_port_forward(*remote_addr)
        self.forwarded.remove(remote_addr)

    def setup(self) -> None:
        # pylint: disable=import-outside-toplevel
        from paramiko import SSHClient, AutoAddPolicy

        self.ssh = SSHClient()
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())
        self.ssh.connect(
            hostname=self.flags.tunnel_hostname,
            port=self.flags.tunnel_port,
            username=self.flags.tunnel_username,
            key_filename=self.flags.tunnel_ssh_key,
            passphrase=self.flags.tunnel_ssh_key_passphrase,
            compress=True,
            timeout=10,
            auth_timeout=7,
        )
        logger.debug(
            "SSH connection established to %s:%d..."
            % (
                self.flags.tunnel_hostname,
                self.flags.tunnel_port,
            ),
        )
        self.transport = self.ssh.get_transport()
        assert self.transport
        sock = cast(socket.socket, self.transport.sock)  # type: ignore[redundant-cast]
        # Enable TCP keep-alive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Keep-alive interval (in seconds)
        if sys.platform != 'darwin':
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        # Keep-alive probe interval (in seconds)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
        # Number of keep-alive probes before timeout
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        self.start_port_forward(('', self.flags.tunnel_remote_port))

    def shutdown(self) -> None:
        for remote_addr in list(self.forwarded):
            self.stop_port_forward(remote_addr)
        self.forwarded.clear()
        if self.transport is not None:
            self.transport.close()
        if self.ssh is not None:
            self.ssh.close()
        self.handler.shutdown()

    def is_alive(self) -> bool:
        return self.transport.is_alive() if self.transport else False

    def is_active(self) -> bool:
        return self.transport.is_active() if self.transport else False
