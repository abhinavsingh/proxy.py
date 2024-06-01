# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Set, Union, Optional
from datetime import datetime


class Metric:
    def __init__(
        self,
                name: str,
                description: Optional[str]=None,
                tags:Set[str] = None,
    ):
        self.timestamp = datetime.utcnow().timestamp()
        self.name = name
        self.description = description
        self.tags = tags


class Counter(Metric):
    def __init__(
        self,
                name:str,
                increment: Union[int, float]=1,
                description: Optional[str]=None,
                tags:Set[str] = None,
    ):
        super().__init__(name, description)
        self.increment = increment


class Gauge(Metric):
    def __init__(
        self,
                name:str,
                value: Union[int, float]=1,
                description: Optional[str]=None,
                tags:Set[str] = None,
    ):
        super().__init__(name, description)
        self.value = value
