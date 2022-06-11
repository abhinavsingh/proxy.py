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
import queue
import socket
import ipaddress
import sys
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Union


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
    RePattern = Any
elif sys.version_info.minor in (7, 8):
    RePattern = re.Pattern  # type: ignore
else:
    RePattern = re.Pattern[Any]  # type: ignore
