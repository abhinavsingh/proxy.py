# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import re
import ssl
import sys
import queue
import socket
import ipaddress
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Union, TypeVar


if TYPE_CHECKING:   # pragma: no cover
    DictQueueType = queue.Queue[Dict[str, Any]]
else:
    DictQueueType = queue.Queue


Selectable = int
Selectables = List[Selectable]
SelectableEvents = Dict[Selectable, int]    # Values are event masks
Readables = Selectables
Writables = Selectables
Descriptors = Tuple[Readables, Writables]
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
TcpOrTlsSocket = Union[ssl.SSLSocket, socket.socket]
HostPort = Tuple[str, int]

if sys.version_info.minor == 6:
    RePattern = TypeVar('RePattern', bound=Any)
elif sys.version_info.minor in (7, 8):
    RePattern = TypeVar('RePattern', bound=re.Pattern)  # type: ignore
else:
    RePattern = TypeVar('RePattern', bound=re.Pattern[Any])  # type: ignore
