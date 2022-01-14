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
import time
import pytest
import tempfile

from pathlib import Path
from typing import Any, Generator
from subprocess import Popen, check_output

from proxy.common.constants import IS_WINDOWS


TLS_INTERCEPTION_FLAGS = ' '.join((
    '--ca-cert-file', 'ca-cert.pem',
    '--ca-key-file', 'ca-key.pem',
    '--ca-signing-key', 'ca-signing-key.pem',
))

PROXY_PY_FLAGS_INTEGRATION = (
    ('--threadless'),
    ('--threadless --local-executor 0'),
    ('--threaded'),
)

PROXY_PY_FLAGS_TLS_INTERCEPTION = (
    ('--threadless ' + TLS_INTERCEPTION_FLAGS),
    ('--threadless --local-executor 0 ' + TLS_INTERCEPTION_FLAGS),
    ('--threaded ' + TLS_INTERCEPTION_FLAGS),
)

PROXY_PY_FLAGS_MODIFY_CHUNK_RESPONSE_PLUGIN = (
    (
        '--threadless --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
        TLS_INTERCEPTION_FLAGS
    ),
    (
        '--threadless --local-executor 0 --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
        TLS_INTERCEPTION_FLAGS
    ),
    # (
    #     '--threaded --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
    #     TLS_INTERCEPTION_FLAGS
    # ),
)

PROXY_PY_FLAGS_MODIFY_POST_DATA_PLUGIN = (
    (
        '--threadless --plugin proxy.plugin.ModifyPostDataPlugin ' +
        TLS_INTERCEPTION_FLAGS
    ),
    (
        '--threadless --local-executor 0 --plugin proxy.plugin.ModifyPostDataPlugin ' +
        TLS_INTERCEPTION_FLAGS
    ),
    (
        '--threaded --plugin proxy.plugin.ModifyPostDataPlugin ' +
        TLS_INTERCEPTION_FLAGS
    ),
)


@pytest.fixture(scope='session', autouse=True)  # type: ignore[misc]
def _gen_ca_certificates() -> None:
    check_output(['make', 'ca-certificates'])


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
    temp_dir = Path(tempfile.gettempdir())
    port_file = temp_dir / 'proxy.port'
    ca_cert_dir = temp_dir / ('certificates-%s' % int(time.time()))
    proxy_cmd = (
        'python', '-m', 'proxy',
        '--hostname', '127.0.0.1',
        '--port', '0',
        '--port-file', str(port_file),
        '--enable-web-server',
        '--num-acceptors', '3',
        '--num-workers', '3',
        '--ca-cert-dir', str(ca_cert_dir),
        '--log-level', 'd',
    ) + tuple(request.param.split())
    proxy_proc = Popen(proxy_cmd)
    # Needed because port file might not be available immediately
    while not port_file.exists():
        time.sleep(1)
    try:
        yield int(port_file.read_text())
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
    PROXY_PY_FLAGS_INTEGRATION,
    indirect=True,
)   # type: ignore[misc]
@pytest.mark.skipif(
    IS_WINDOWS,
    reason='OSError: [WinError 193] %1 is not a valid Win32 application',
)  # type: ignore[misc]
def test_integration(proxy_py_subprocess: int) -> None:
    """An acceptance test using ``curl`` through proxy.py."""
    this_test_module = Path(__file__)
    shell_script_test = this_test_module.with_suffix('.sh')
    check_output([str(shell_script_test), str(proxy_py_subprocess)])


@pytest.mark.smoke  # type: ignore[misc]
@pytest.mark.parametrize(
    'proxy_py_subprocess',
    PROXY_PY_FLAGS_TLS_INTERCEPTION,
    indirect=True,
)   # type: ignore[misc]
@pytest.mark.skipif(
    IS_WINDOWS,
    reason='OSError: [WinError 193] %1 is not a valid Win32 application',
)  # type: ignore[misc]
def test_integration_with_interception_flags(proxy_py_subprocess: int) -> None:
    """An acceptance test for TLS interception using ``curl`` through proxy.py."""
    shell_script_test = Path(__file__).parent / 'test_interception.sh'
    check_output([str(shell_script_test), str(proxy_py_subprocess)])


@pytest.mark.smoke  # type: ignore[misc]
@pytest.mark.parametrize(
    'proxy_py_subprocess',
    PROXY_PY_FLAGS_MODIFY_CHUNK_RESPONSE_PLUGIN,
    indirect=True,
)   # type: ignore[misc]
@pytest.mark.skipif(
    IS_WINDOWS,
    reason='OSError: [WinError 193] %1 is not a valid Win32 application',
)  # type: ignore[misc]
def test_modify_chunk_response_integration(proxy_py_subprocess: int) -> None:
    """An acceptance test for :py:class:`~proxy.plugin.ModifyChunkResponsePlugin`
    interception using ``curl`` through proxy.py."""
    shell_script_test = Path(__file__).parent / 'test_modify_chunk_response.sh'
    check_output([str(shell_script_test), str(proxy_py_subprocess)])


@pytest.mark.smoke  # type: ignore[misc]
@pytest.mark.parametrize(
    'proxy_py_subprocess',
    PROXY_PY_FLAGS_MODIFY_POST_DATA_PLUGIN,
    indirect=True,
)   # type: ignore[misc]
@pytest.mark.skipif(
    IS_WINDOWS,
    reason='OSError: [WinError 193] %1 is not a valid Win32 application',
)  # type: ignore[misc]
def test_modify_post_response_integration(proxy_py_subprocess: int) -> None:
    """An acceptance test for :py:class:`~proxy.plugin.ModifyPostDataPlugin`
    interception using ``curl`` through proxy.py."""
    shell_script_test = Path(__file__).parent / 'test_modify_post_data.sh'
    check_output([str(shell_script_test), str(proxy_py_subprocess)])
