# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import contextlib
import os
import uuid
import subprocess
import tempfile
import logging
from typing import List, Generator

from .utils import bytes_
from .constants import COMMA


logger = logging.getLogger(__name__)


@contextlib.contextmanager
def ssl_config(cnames: List[str]) -> Generator[str, None, None]:
    with open('/etc/ssl/openssl.cnf', 'rb') as cnf:
        config = cnf.read()
    config += b'\n[SAN]\nsubjectAltName='
    alt_names = []
    for cname in cnames:
        alt_names.append(b'DNS:%s' % bytes_(cname))
    config += COMMA.join(alt_names)
    config_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex)
    with open(config_path, 'wb') as cnf:
        cnf.write(config)
    yield config_path
    os.remove(config_path)


def gen_private_key(
        key_path: str,
        bits: int = 2048,
        timeout: int = 10,
        password: str = 'proxy.py') -> bool:
    """Generates a private key."""
    command = [
        'openssl', 'genrsa', '-aes256',
        '-passout', 'pass:%s' % password,
        '-out', key_path, str(bits)
    ]
    cmd = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    cmd.communicate(timeout=timeout)
    assert cmd.returncode == 0
    return True


def gen_public_key(
        public_key_path: str,
        private_key_path: str,
        subject: str = '/C=US/ST=CA/L=SF/O=Proxy/OU=Eng/CN=proxy.py',
        days: int = 365,
        timeout: int = 10,
        password: str = 'proxy.py') -> bool:
    """For a given private key, generates a corresponding public key."""
    with ssl_config(['proxy.py', 'www.proxy.py']) as config_path:
        command = [
            'openssl', 'req', '-new', '-x509', '-sha256',
            '-days', str(days), '-subj', subject,
            '-passin', 'pass:%s' % password,
            '-reqexts', 'SAN', '-extensions', 'SAN',
            '-config', config_path,
            '-key', private_key_path, '-out', public_key_path
        ]
        cmd = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        cmd.communicate(timeout=timeout)
    assert cmd.returncode == 0
    return True
