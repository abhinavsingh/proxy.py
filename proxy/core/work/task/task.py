class Task:
    """Task object which known how to process the payload."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        print(payload)
