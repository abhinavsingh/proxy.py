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
import subprocess

from pathlib import Path
from typing import Any, Generator
from subprocess import Popen, check_output

from proxy.common.constants import IS_WINDOWS


def _https_server_flags() -> str:
    return ' '.join((
        '--key-file', 'https-key.pem',
        '--cert-file', 'https-signed-cert.pem',
    ))


def _tls_interception_flags(ca_cert_suffix: str = '') -> str:
    return ' '.join((
        '--ca-cert-file', 'ca-cert%s.pem' % ca_cert_suffix,
        '--ca-key-file', 'ca-key%s.pem' % ca_cert_suffix,
        '--ca-signing-key', 'ca-signing-key%s.pem' % ca_cert_suffix,
    ))


PROXY_PY_FLAGS_INTEGRATION = (
    ('--threadless'),
    ('--threadless --local-executor 0'),
    ('--threaded'),
)

PROXY_PY_HTTPS = (
    ('--threadless ' + _https_server_flags()),
    ('--threadless --local-executor 0 ' + _https_server_flags()),
    ('--threaded ' + _https_server_flags()),
)

PROXY_PY_FLAGS_TLS_INTERCEPTION = (
    ('--threadless ' + _tls_interception_flags()),
    ('--threadless --local-executor 0 ' + _tls_interception_flags()),
    ('--threaded ' + _tls_interception_flags()),
)

PROXY_PY_FLAGS_MODIFY_CHUNK_RESPONSE_PLUGIN = (
    (
        '--threadless --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
        _tls_interception_flags('-chunk')
    ),
    (
        '--threadless --local-executor 0 --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
        _tls_interception_flags('-chunk')
    ),
    (
        '--threaded --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
        _tls_interception_flags('-chunk')
    ),
)

PROXY_PY_FLAGS_MODIFY_POST_DATA_PLUGIN = (
    (
        '--threadless --plugin proxy.plugin.ModifyPostDataPlugin ' +
        _tls_interception_flags('-post')
    ),
    (
        '--threadless --local-executor 0 --plugin proxy.plugin.ModifyPostDataPlugin ' +
        _tls_interception_flags('-post')
    ),
    (
        '--threaded --plugin proxy.plugin.ModifyPostDataPlugin ' +
        _tls_interception_flags('-post')
    ),
)


@pytest.fixture(scope='session', autouse=True)  # type: ignore[misc]
def _gen_https_certificates(request: Any) -> None:
    check_output([
        'make', 'https-certificates',
    ])
    check_output([
        'make', 'sign-https-certificates',
    ])


@pytest.fixture(scope='session', autouse=True)  # type: ignore[misc]
def _gen_ca_certificates(request: Any) -> None:
    check_output([
        'make', 'ca-certificates',
    ])
    check_output([
        'make', 'ca-certificates',
        '-e', 'CA_CERT_SUFFIX=-chunk',
    ])
    check_output([
        'make', 'ca-certificates',
        '-e', 'CA_CERT_SUFFIX=-post',
    ])


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
        '--plugin', 'proxy.plugin.WebServerPlugin',
        '--num-acceptors', '3',
        '--num-workers', '3',
        '--ca-cert-dir', str(ca_cert_dir),
        '--log-level', 'd',
    ) + tuple(request.param.split())
    proxy_proc = Popen(proxy_cmd, stderr=subprocess.STDOUT)
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
    PROXY_PY_HTTPS,
    indirect=True,
)   # type: ignore[misc]
@pytest.mark.skipif(
    IS_WINDOWS,
    reason='OSError: [WinError 193] %1 is not a valid Win32 application',
)  # type: ignore[misc]
def test_https_integration(proxy_py_subprocess: int) -> None:
    """An acceptance test for HTTPS web and proxy server using ``curl`` through proxy.py."""
    this_test_module = Path(__file__)
    shell_script_test = this_test_module.with_suffix('.sh')
    # "1" means use-https scheme for requests to instance
    check_output([str(shell_script_test), str(proxy_py_subprocess), '1'])


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
