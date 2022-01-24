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
