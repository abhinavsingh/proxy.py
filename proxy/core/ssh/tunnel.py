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
from typing import Callable, Optional, Tuple

import paramiko


logger = logging.getLogger(__name__)


class Tunnel:
    """Establishes a tunnel between local (machine where Tunnel is running) and remote host.
    Once a tunnel has been established, remote host can route HTTP(s) traffic to
    ``localhost`` over tunnel.
    """

    def __init__(
            self,
            ssh_username: str,
            remote_addr: Tuple[str, int],
            private_pem_key: str,
            remote_proxy_port: int,
            conn_handler: Callable[[paramiko.channel.Channel], None],
    ) -> None:
        self.remote_addr = remote_addr
        self.ssh_username = ssh_username
        self.private_pem_key = private_pem_key
        self.remote_proxy_port = remote_proxy_port
        self.conn_handler = conn_handler

    def run(self) -> None:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            ssh.connect(
                hostname=self.remote_addr[0],
                port=self.remote_addr[1],
                username=self.ssh_username,
                key_filename=self.private_pem_key,
            )
            logger.info('SSH connection established...')
            transport: Optional[paramiko.transport.Transport] = ssh.get_transport(
            )
            assert transport is not None
            transport.request_port_forward('', self.remote_proxy_port)
            logger.info('Tunnel port forward setup successful...')
            while True:
                conn: Optional[paramiko.channel.Channel] = transport.accept(
                    timeout=1,
                )
                assert conn is not None
                e = transport.get_exception()
                if e:
                    raise e
                if conn is None:
                    continue
                self.conn_handler(conn)
        except KeyboardInterrupt:
            pass
        finally:
            ssh.close()
