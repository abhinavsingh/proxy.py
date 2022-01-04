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
import ipaddress
import sys

from typing import TYPE_CHECKING, Dict, Any, List, Tuple, Union

# NOTE: Using try/except causes linting problems which is why it's necessary
# NOTE: to use this mypy/pylint idiom for py36-py38 compatibility
# Ref: https://github.com/python/typeshed/issues/3500#issuecomment-560958608
if sys.version_info >= (3, 8):
    from typing import Protocol
else:
    from typing_extensions import Protocol


if TYPE_CHECKING:
    DictQueueType = queue.Queue[Dict[str, Any]]    # pragma: no cover
else:
    DictQueueType = queue.Queue


class HasFileno(Protocol):
    def fileno(self) -> int:
        ...     # pragma: no cover


Readables = List[Union[int, HasFileno]]
Writables = List[Union[int, HasFileno]]
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Descriptors = Tuple[List[int], List[int]]
