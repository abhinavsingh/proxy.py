# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    Test the simplest proxy use scenario for smoke.
"""
from pathlib import Path
from subprocess import check_output, Popen
from typing import Generator, Any

import pytest

from proxy.common.utils import get_available_port
from proxy.common._compat import IS_WINDOWS  # noqa: WPS436


# FIXME: Ignore is necessary for as long as pytest hasn't figured out
# FIXME: typing for their fixtures.
# Refs:
# * https://github.com/pytest-dev/pytest/issues/7469#issuecomment-918345196
# * https://github.com/pytest-dev/pytest/issues/3342
@pytest.fixture  # type: ignore[misc]
def proxy_py_subprocess(request: Any) -> Generator[int, None, None]:
    """Instantiate proxy.py in a subprocess for testing.

    NOTE: Doesn't waits for the proxy to startup.
    Ensure instance check in your tests.

    After the testing is over, tear it down.
    """
    port = get_available_port()
    proxy_cmd = (
        'python', '-m', 'proxy',
        '--hostname', '127.0.0.1',
        '--port', str(port),
        '--enable-web-server',
    ) + tuple(request.param.split())
    proxy_proc = Popen(proxy_cmd)
    try:
        yield port
    finally:
        proxy_proc.terminate()
        proxy_proc.wait()


# FIXME: Ignore is necessary for as long as pytest hasn't figured out
# FIXME: typing for their fixtures.
# Refs:
# * https://github.com/pytest-dev/pytest/issues/7469#issuecomment-918345196
# * https://github.com/pytest-dev/pytest/issues/3342
@pytest.mark.smoke  # type: ignore[misc]
@pytest.mark.parametrize(
    'proxy_py_subprocess',
    (
        ('--threadless'),
        ('--threadless --local-executor'),
        ('--threaded'),
    ),
    indirect=True,
)   # type: ignore[misc]
@pytest.mark.xfail(
    IS_WINDOWS,
    reason='OSError: [WinError 193] %1 is not a valid Win32 application',
    raises=OSError,
)  # type: ignore[misc]
def test_curl(proxy_py_subprocess: int) -> None:
    """An acceptance test with using ``curl`` through proxy.py."""
    this_test_module = Path(__file__)
    shell_script_test = this_test_module.with_suffix('.sh')
    check_output([str(shell_script_test), str(proxy_py_subprocess)])
