# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import queue
from typing import TYPE_CHECKING, Dict, Any


if TYPE_CHECKING:
    DictQueueType = queue.Queue[Dict[str, Any]]    # pragma: no cover
else:
    DictQueueType = queue.Queue
