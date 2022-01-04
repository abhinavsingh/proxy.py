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

from typing import TYPE_CHECKING, Dict, Any, List, Tuple, Union


if TYPE_CHECKING:
    DictQueueType = queue.Queue[Dict[str, Any]]    # pragma: no cover
else:
    DictQueueType = queue.Queue


Selectables = List[int]
Readables = Selectables
Writables = Selectables
Descriptors = Tuple[Readables, Writables]

IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
