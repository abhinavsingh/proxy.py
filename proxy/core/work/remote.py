# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import asyncio
import logging
from typing import Any, Optional


logger = logging.getLogger(__name__)


class RemoteExecutor:
    """A threadless executor implementation which receives work over a connection.

    NOTE: RemoteExecutor uses ``recv_handle`` to accept file descriptors.

    TODO: Refactor and abstract ``recv_handle`` part so that a threaded
    remote executor can also accept work over a connection.  Currently,
    remote executors must be running in a process.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def loop(self) -> Optional[asyncio.AbstractEventLoop]:
        if self._loop is None:
            self._loop = asyncio.get_event_loop_policy().get_event_loop()
        return self._loop
