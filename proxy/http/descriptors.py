# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from ..common.types import Readables, Writables, Descriptors


class DescriptorsHandlerMixin:
    """DescriptorsHandlerMixin provides abstraction used by several core HTTP modules
    include web and proxy plugins.  By using DescriptorsHandlerMixin, class
    becomes complaint with core event loop."""

    # TODO(abhinavsingh): get_descriptors, write_to_descriptors, read_from_descriptors
    # can be placed into their own abstract class which can then be shared by
    # HttpProxyBasePlugin, HttpWebServerBasePlugin and HttpProtocolHandlerPlugin class.
    #
    # Currently code has been shamelessly copied.  Also these methods are not
    # marked as abstract to avoid breaking custom plugins written by users for
    # previous versions of proxy.py
    #
    # Since 3.4.0
    #
    # @abstractmethod
    async def get_descriptors(self) -> Descriptors:
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

    # @abstractmethod
    # def get_descriptors(self) -> Descriptors:
    #     """Implementations must return a list of descriptions that they wish to
    #     read from and write into."""
    #     return [], []  # pragma: no cover

    # @abstractmethod
    # async def write_to_descriptors(self, w: Writables) -> bool:
    #     """Implementations must now write/flush data over the socket.

    #     Note that buffer management is in-build into the connection classes.
    #     Hence implementations MUST call
    #     :meth:`~proxy.core.connection.TcpConnection.flush` here, to send
    #     any buffered data over the socket.
    #     """
    #     return False  # pragma: no cover

    # @abstractmethod
    # async def read_from_descriptors(self, r: Readables) -> bool:
    #     """Implementations must now read data over the socket."""
    #     return False  # pragma: no cover

    # TODO(abhinavsingh): get_descriptors, write_to_descriptors, read_from_descriptors
    # can be placed into their own abstract class which can then be shared by
    # HttpProxyBasePlugin, HttpWebServerBasePlugin and HttpProtocolHandlerPlugin class.
    #
    # Currently code has been shamelessly copied.  Also these methods are not
    # marked as abstract to avoid breaking custom plugins written by users for
    # previous versions of proxy.py
    #
    # Since 3.4.0
    #
    # @abstractmethod
    # def get_descriptors(self) -> Descriptors:
    #     return [], []  # pragma: no cover

    # # @abstractmethod
    # def write_to_descriptors(self, w: Writables) -> bool:
    #     """Implementations must now write/flush data over the socket.

    #     Note that buffer management is in-build into the connection classes.
    #     Hence implementations MUST call
    #     :meth:`~proxy.core.connection.connection.TcpConnection.flush`
    #     here, to send any buffered data over the socket.
    #     """
    #     return False  # pragma: no cover

    # # @abstractmethod
    # def read_from_descriptors(self, r: Readables) -> bool:
    #     """Implementations must now read data over the socket."""
    #     return False  # pragma: no cover
