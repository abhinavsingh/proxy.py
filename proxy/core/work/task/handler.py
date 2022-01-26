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

from .task import Task
from ..work import Work


class TaskHandler(Work[Task]):
    """Task handler."""

    @staticmethod
    def create(*args: Any) -> Task:
        """Work core doesn't know how to create work objects for us.
        Example, for task module scenario, it doesn't know how to create
        Task objects for us."""
        return Task(*args)
