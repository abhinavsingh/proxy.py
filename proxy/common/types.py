# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import queue

from typing import TYPE_CHECKING, Dict, Any

from typing_extensions import Protocol

if TYPE_CHECKING:
    DictQueueType = queue.Queue[Dict[str, Any]]    # pragma: no cover
else:
    DictQueueType = queue.Queue


class HasFileno(Protocol):
    def fileno(self) -> int:
        ...     # pragma: no cover
