class Result:
    def __init__(self, reason: str = None):
        self._reason = reason

    def __bool__(self) -> bool:
        return self._reason is None

    def __str__(self) -> str:
        return self._reason if self._reason is not None else ""
