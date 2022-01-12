# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any
from ..common.types import Readables, Writables, Descriptors


# Since 3.4.0
class DescriptorsHandlerMixin:
    """DescriptorsHandlerMixin provides abstraction used by several core HTTP modules
    include web and proxy plugins.  By using DescriptorsHandlerMixin, class
    becomes complaint with core event loop."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # FIXME: Required for multi-level inheritance to work
        super().__init__(*args, **kwargs)   # type: ignore

    # @abstractmethod
    async def get_descriptors(self) -> Descriptors:
        """Implementations must return a list of descriptions that they wish to
        read from and write into."""
        return [], []  # pragma: no cover

    # @abstractmethod
    async def write_to_descriptors(self, w: Writables) -> bool:
        """Implementations must now write/flush data over the socket.

        Note that buffer management is in-build into the connection classes.
        Hence implementations MUST call
        :meth:`~proxy.core.connection.connection.TcpConnection.flush`
        here, to send any buffered data over the socket.
        """
        return False  # pragma: no cover

    # @abstractmethod
    async def read_from_descriptors(self, r: Readables) -> bool:
        """Implementations must now read data over the socket."""
        return False  # pragma: no cover
