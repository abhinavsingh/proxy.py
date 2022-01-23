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
import subprocess
from typing import Any, Dict, Optional

from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser
from ..common.utils import text_
from ..common.constants import IS_WINDOWS


class ProgramNamePlugin(HttpProxyBasePlugin):
    """Tries to identify the application connecting to the
    proxy instance.  This is only possible when connection
    itself originates from the same machine where the proxy
    instance is running."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.program_name: Optional[str] = None

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if IS_WINDOWS:
            raise NotImplementedError()
        assert self.client.addr
        if self.client.addr[0] in ('::1', '127.0.0.1'):
            assert self.client.addr
            port = self.client.addr[1]
            ls = subprocess.Popen(
                ('lsof', '-i', '-P', '-n'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                output = subprocess.check_output(
                    ('grep', '{0}'.format(port)),
                    stdin=ls.stdout,
                )
                port_programs = output.splitlines()
                for program in port_programs:
                    parts = program.split()
                    if int(parts[1]) != os.getpid():
                        self.program_name = text_(parts[0])
                        break
            except subprocess.CalledProcessError:
                pass
            finally:
                ls.wait(timeout=1)
        if self.program_name is None:
            self.program_name = self.client.addr[0]
        return request

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        context.update({'client_ip': self.program_name})
        return context
