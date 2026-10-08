"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import pytest


@pytest.fixture(autouse=True)   # type: ignore[misc]
def _event_loop_before_mocks(request: pytest.FixtureRequest) -> None:
    """Create the asyncio event loop before test fixtures mock sockets.

    Since pytest-asyncio 1.0, the event loop runner fixture is set up only
    after all other fixtures of a test.  Several test classes patch
    ``socket.socket`` and ``selectors.DefaultSelector`` in autouse fixtures,
    which breaks the creation of the event loop.  Conftest autouse fixtures
    are instantiated first, so set up the runner here.
    """
    if request.node.get_closest_marker('asyncio') is None:
        return
    request.getfixturevalue('_function_scoped_runner')
