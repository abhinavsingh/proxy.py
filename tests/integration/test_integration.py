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
import os
import sys
import time
import tempfile
import subprocess
from random import random
from typing import Any, List, Generator
from pathlib import Path
from subprocess import Popen
from subprocess import run as _run

import pytest

from proxy.common.constants import IS_WINDOWS


TEMP_DIR = Path(tempfile.gettempdir())
CERT_DIR = TEMP_DIR / 'certificates'
os.makedirs(CERT_DIR, exist_ok=True)


def run(args: List[Any], **kwargs: Any) -> None:
    args = args if not IS_WINDOWS else ['powershell'] + args
    _run(args, check=True, stderr=subprocess.STDOUT, **kwargs)


def _https_server_flags() -> str:
    return ' '.join((
        '--key-file', str(CERT_DIR / 'https-key.pem'),
        '--cert-file', str(CERT_DIR / 'https-signed-cert.pem'),
    ))


def _tls_interception_flags(ca_cert_suffix: str = '') -> str:
    return ' '.join((
        '--ca-cert-file', str(CERT_DIR / ('ca-cert%s.pem' % ca_cert_suffix)),
        '--ca-key-file', str(CERT_DIR / ('ca-key%s.pem' % ca_cert_suffix)),
        '--ca-signing-key', str(
            CERT_DIR /
            ('ca-signing-key%s.pem' % ca_cert_suffix),
        ),
    ))


_PROXY_PY_FLAGS_INTEGRATION = [
    ('--threaded'),
]
if not IS_WINDOWS:
    _PROXY_PY_FLAGS_INTEGRATION += [
        ('--threadless --local-executor 0'),
        ('--threadless'),
    ]
PROXY_PY_FLAGS_INTEGRATION = tuple(_PROXY_PY_FLAGS_INTEGRATION)

_PROXY_PY_HTTPS = [
    ('--threaded ' + _https_server_flags()),
]
if not IS_WINDOWS:
    _PROXY_PY_HTTPS += [
        ('--threadless --local-executor 0 ' + _https_server_flags()),
        ('--threadless ' + _https_server_flags()),
    ]
PROXY_PY_HTTPS = tuple(_PROXY_PY_HTTPS)

_PROXY_PY_FLAGS_TLS_INTERCEPTION = [
    ('--threaded ' + _tls_interception_flags()),
]
if not IS_WINDOWS:
    _PROXY_PY_FLAGS_TLS_INTERCEPTION += [
        ('--threadless --local-executor 0 ' + _tls_interception_flags()),
        ('--threadless ' + _tls_interception_flags()),
    ]
PROXY_PY_FLAGS_TLS_INTERCEPTION = tuple(_PROXY_PY_FLAGS_TLS_INTERCEPTION)

_PROXY_PY_FLAGS_MODIFY_CHUNK_RESPONSE_PLUGIN = [
    (
        '--threaded --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
        _tls_interception_flags('-chunk')
    ),
]
if not IS_WINDOWS:
    _PROXY_PY_FLAGS_MODIFY_CHUNK_RESPONSE_PLUGIN += [
        (
            '--threadless --local-executor 0 --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
            _tls_interception_flags('-chunk')
        ),
        (
            '--threadless --plugin proxy.plugin.ModifyChunkResponsePlugin ' +
            _tls_interception_flags('-chunk')
        ),
    ]
PROXY_PY_FLAGS_MODIFY_CHUNK_RESPONSE_PLUGIN = tuple(
    _PROXY_PY_FLAGS_MODIFY_CHUNK_RESPONSE_PLUGIN,
)

_PROXY_PY_FLAGS_MODIFY_POST_DATA_PLUGIN = [
    (
        '--threaded --plugin proxy.plugin.ModifyPostDataPlugin ' +
        _tls_interception_flags('-post')
    ),
]
if not IS_WINDOWS:
    _PROXY_PY_FLAGS_MODIFY_POST_DATA_PLUGIN += [
        (
            '--threadless --local-executor 0 --plugin proxy.plugin.ModifyPostDataPlugin ' +
            _tls_interception_flags('-post')
        ),
        (
            '--threadless --plugin proxy.plugin.ModifyPostDataPlugin ' +
            _tls_interception_flags('-post')
        ),
    ]
PROXY_PY_FLAGS_MODIFY_POST_DATA_PLUGIN = tuple(
    _PROXY_PY_FLAGS_MODIFY_POST_DATA_PLUGIN,
)


@pytest.fixture(scope='session', autouse=not IS_WINDOWS)  # type: ignore[misc]
def _gen_https_certificates(request: Any) -> None:
    run([
        'make', 'https-certificates',
        '-e', 'PYTHON="%s"' % (sys.executable,),
        '-e', 'CERT_DIR=%s/' % (str(CERT_DIR)),
    ])
    run([
        'make', 'sign-https-certificates',
        '-e', 'PYTHON="%s"' % (sys.executable,),
        '-e', 'CERT_DIR=%s/' % (str(CERT_DIR)),
    ])


@pytest.fixture(scope='session', autouse=not IS_WINDOWS)  # type: ignore[misc]
def _gen_ca_certificates(request: Any) -> None:
    run([
        'make', 'ca-certificates',
        '-e', 'PYTHON="%s"' % (sys.executable,),
        '-e', 'CERT_DIR=%s/' % (str(CERT_DIR)),
    ])
    run([
        'make', 'ca-certificates',
        '-e', 'PYTHON="%s"' % (sys.executable,),
        '-e', 'CA_CERT_SUFFIX=-chunk',
        '-e', 'CERT_DIR=%s/' % (str(CERT_DIR)),
    ])
    run([
        'make', 'ca-certificates',
        '-e', 'PYTHON="%s"' % (sys.executable,),
        '-e', 'CA_CERT_SUFFIX=-post',
        '-e', 'CERT_DIR=%s/' % (str(CERT_DIR)),
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
    run_id = str(int(time.time())) + '-' + str(int(random() * pow(10, 6)))
    port_file = TEMP_DIR / ('proxy-%s.port' % run_id)
    ca_cert_dir = TEMP_DIR / ('certificates-%s' % run_id)
    os.makedirs(ca_cert_dir, exist_ok=True)
    proxy_cmd = (
        sys.executable, '-m', 'proxy',
        '--hostname', '127.0.0.1',
        '--port', '0',
        '--port-file', str(port_file),
        '--enable-web-server',
        '--plugin', 'proxy.plugin.WebServerPlugin',
        '--enable-reverse-proxy',
        '--plugin', 'proxy.plugin.ReverseProxyPlugin',
        '--num-acceptors', '3',
        '--num-workers', '3',
        '--ca-cert-dir', str(ca_cert_dir),
        '--log-level', 'd',
    ) + tuple(request.param.split())
    proxy_proc = Popen(proxy_cmd, stderr=subprocess.STDOUT)
    # Needed because port file might not be available immediately
    retries = 0
    while not port_file.exists() and retries < 8:
        time.sleep(1)
        retries += 1
    if not port_file.exists():
        raise RuntimeError('proxy.py failed to boot up')
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
def test_integration(proxy_py_subprocess: int) -> None:
    """An acceptance test using ``curl`` through proxy.py."""
    this_test_module = Path(__file__)
    shell_script_test = this_test_module.with_suffix('.sh')
    print('shell_script_test %s' % shell_script_test)
    print('proxy_py_subprocess %s' % proxy_py_subprocess)
    run([str(shell_script_test), str(proxy_py_subprocess)], stdout=sys.stdout.buffer)


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
    run([str(shell_script_test), str(proxy_py_subprocess), '1'])


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
    run([
        str(shell_script_test),
        str(proxy_py_subprocess),
        str(CERT_DIR),
    ])


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
    run([
        str(shell_script_test),
        str(proxy_py_subprocess),
        str(CERT_DIR),
    ])


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
    run([
        str(shell_script_test),
        str(proxy_py_subprocess),
        str(CERT_DIR),
    ])
