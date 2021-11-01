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
import threading
from typing import Optional

from paramiko import SSHClient, AutoAddPolicy
from paramiko.channel import Channel
from paramiko.transport import Transport

from ...http.handler import HttpProtocolHandler
from ...common.flag import flags

from .client import TunnelClientConnection

flags.add_argument(
    '--tunnel-hostname',
    type=str,
    default=None,
    help='Default: None. Remote hostname or IP address to which SSH tunnel will be established.')
flags.add_argument(
    '--tunnel-port',
    type=int,
    default=22,
    help='Default: 22. SSH port of the remote host.')
flags.add_argument(
    '--tunnel-username',
    type=str,
    default=None,
    help='Default: None. Username to use for establishing SSH tunnel.')
flags.add_argument(
    '--tunnel-ssh-key',
    type=str,
    default=None,
    help='Default: None. Private key path in pem format')
flags.add_argument(
    '--tunnel-ssh-key-passphrase',
    type=str,
    default=None,
    help='Default: None. Private key passphrase')
flags.add_argument(
    '--tunnel-remote-port',
    type=int,
    default=8899,
    help='Default: 8899. Remote port which will be forwarded locally for proxy.')


class TunnelAcceptorPool:
    """Establishes a tunnel between local (machine where Tunnel is running) and remote host.
    Once a tunnel has been established, remote host can route HTTP(s) traffic to
    localhost over tunnel.
    """

    def __init__(self, flags: argparse.Namespace) -> None:
        self.flags = flags

    def run(self) -> None:
        ssh = SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh.connect(
                hostname=self.flags.tunnel_hostname,
                port=self.flags.tunnel_port,
                username=self.flags.tunnel_username,
                key_filename=self.flags.tunnel_ssh_key,
                passphrase=self.flags.tunnel_ssh_key_passphrase,
            )
            print('SSH connection established...')
            transport: Optional[Transport] = ssh.get_transport()
            assert transport is not None
            transport.request_port_forward('', self.flags.tunnel_remote_port)
            print('Tunnel port forward setup successful...')
            while True:
                chan: Optional[Channel] = transport.accept(timeout=1)
                e = transport.get_exception()
                if e:
                    raise e
                if chan is None:
                    continue
                conn = TunnelClientConnection(chan)
                work = HttpProtocolHandler(
                    conn,
                    flags=self.flags,
                    event_queue=None
                )
                work_thread = threading.Thread(target=work.run)
                work_thread.daemon = True
                work_thread.start()
        except KeyboardInterrupt:
            pass
        finally:
            ssh.close()
