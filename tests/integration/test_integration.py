"""Test the simplest proxy use scenario for smoke."""
from pathlib import Path
from subprocess import check_output, Popen
from typing import Generator

import pytest

from proxy.common._compat import IS_WINDOWS  # noqa: WPS436


# FIXME: Ignore is necessary for as long as pytest hasn't figured out
# FIXME: typing for their fixtures.
# Refs:
# * https://github.com/pytest-dev/pytest/issues/7469#issuecomment-918345196
# * https://github.com/pytest-dev/pytest/issues/3342
@pytest.fixture  # type: ignore[misc]
def _proxy_py_instance() -> Generator[None, None, None]:
    """Instantiate proxy.py in a subprocess for testing.

    After the testing is over, tear it down.
    """
    proxy_cmd = (
        'proxy',
        '--hostname', '127.0.0.1',
        '--enable-web-server',
    )
    proxy_proc = Popen(proxy_cmd)
    try:
        yield
    finally:
        proxy_proc.terminate()
        proxy_proc.wait(1)


# FIXME: Ignore is necessary for as long as pytest hasn't figured out
# FIXME: typing for their fixtures.
# Refs:
# * https://github.com/pytest-dev/pytest/issues/7469#issuecomment-918345196
# * https://github.com/pytest-dev/pytest/issues/3342
@pytest.mark.smoke  # type: ignore[misc]
@pytest.mark.usefixtures('_proxy_py_instance')  # type: ignore[misc]
@pytest.mark.xfail(
    IS_WINDOWS,
    reason='OSError: [WinError 193] %1 is not a valid Win32 application',
    raises=OSError,
)  # type: ignore[misc]
def test_curl() -> None:
    """An acceptance test with using ``curl`` through proxy.py."""
    this_test_module = Path(__file__)
    shell_script_test = this_test_module.with_suffix('.sh')

    check_output(str(shell_script_test))
