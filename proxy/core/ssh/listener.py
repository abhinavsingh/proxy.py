# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
import argparse
from typing import TYPE_CHECKING, Any, Set, Tuple, Callable, Optional


try:
    from paramiko import SSHClient, AutoAddPolicy
    from paramiko.transport import Transport
    if TYPE_CHECKING:   # pragma: no cover
        from paramiko.channel import Channel
except ImportError:     # pragma: no cover
    pass

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


class SshTunnelListener:
    """Connects over SSH and forwards a remote port to local host.

    Incoming connections are delegated to provided callback."""

    def __init__(
            self,
            flags: argparse.Namespace,
            on_connection_callback: Callable[['Channel', Tuple[str, int], Tuple[str, int]], None],
    ) -> None:
        self.flags = flags
        self.on_connection_callback = on_connection_callback
        self.ssh: Optional[SSHClient] = None
        self.transport: Optional[Transport] = None
        self.forwarded: Set[Tuple[str, int]] = set()

    def start_port_forward(self, remote_addr: Tuple[str, int]) -> None:
        assert self.transport is not None
        self.transport.request_port_forward(
            *remote_addr,
            handler=self.on_connection_callback,
        )
        self.forwarded.add(remote_addr)
        logger.info('%s:%d forwarding successful...' % remote_addr)

    def stop_port_forward(self, remote_addr: Tuple[str, int]) -> None:
        assert self.transport is not None
        self.transport.cancel_port_forward(*remote_addr)
        self.forwarded.remove(remote_addr)

    def __enter__(self) -> 'SshTunnelListener':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def setup(self) -> None:
        self.ssh = SSHClient()
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())
        self.ssh.connect(
            hostname=self.flags.tunnel_hostname,
            port=self.flags.tunnel_port,
            username=self.flags.tunnel_username,
            key_filename=self.flags.tunnel_ssh_key,
            passphrase=self.flags.tunnel_ssh_key_passphrase,
        )
        logger.info(
            'SSH connection established to %s:%d...' % (
                self.flags.tunnel_hostname,
                self.flags.tunnel_port,
            ),
        )
        self.transport = self.ssh.get_transport()

    def shutdown(self) -> None:
        for remote_addr in list(self.forwarded):
            self.stop_port_forward(remote_addr)
        self.forwarded.clear()
        if self.transport is not None:
            self.transport.close()
        if self.ssh is not None:
            self.ssh.close()
