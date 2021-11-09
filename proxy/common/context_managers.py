# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Optional, Type


class SetupShutdownContextManager(ABC):
    """An abstract context manager which expects
    implementations to provide a setup() and shutdown()
    implementation instead of __enter__ and __exit__ methods.

    Note that, currently, SetupShutdownContextManager by
    default return instance of the class and doesn't provide
    implementations to override and return anything else.

    If you want to return anything else but the class instance,
    do not use SetupShutdownContextManager.
    """

    def __enter__(self) -> 'SetupShutdownContextManager':
        self.setup()
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType],
    ) -> None:
        self.shutdown()

    @abstractmethod
    def setup(self) -> None:
        raise NotImplementedError()

    def shutdown(self) -> None:
        raise NotImplementedError()
