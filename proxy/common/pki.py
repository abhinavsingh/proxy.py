# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling:word-list::

       pki
"""
import os
import sys
import time
import uuid
import logging
import argparse
import tempfile
import contextlib
import subprocess
from typing import List, Tuple, Optional, Generator

from .utils import bytes_
from .version import __version__
from .constants import COMMA


logger = logging.getLogger(__name__)


DEFAULT_CONFIG = b'''[ req ]
#default_bits		= 2048
#default_md		    = sha256
#default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		    = req_attributes

[ req_distinguished_name ]
countryName			    = Country Name (2 letter code)
countryName_min			= 2
countryName_max			= 2
stateOrProvinceName		= State or Province Name (full name)
localityName			= Locality Name (eg, city)
organizationName		= Organization Name (eg, company)
organizationalUnitName	= Organizational Unit Name (eg, section)
commonName			    = Common Name (eg, fully qualified host name)
commonName_max			= 64
emailAddress			= Email Address
emailAddress_max		= 64

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min	= 4
challengePassword_max	= 20'''


def remove_passphrase(
        key_in_path: str,
        password: str,
        key_out_path: str,
        timeout: int = 10,
        openssl: str = 'openssl',
) -> bool:
    """Remove passphrase from a private key."""
    command = [
        openssl, 'rsa',
        '-passin', 'pass:%s' % password,
        '-in', key_in_path,
        '-out', key_out_path,
    ]
    return run_openssl_command(command, timeout)


def gen_private_key(
        key_path: str,
        password: str,
        bits: int = 2048,
        timeout: int = 10,
        openssl: str = 'openssl',
) -> bool:
    """Generates a private key."""
    command = [
        openssl, 'genrsa', '-aes256',
        '-passout', 'pass:%s' % password,
        '-out', key_path, str(bits),
    ]
    return run_openssl_command(command, timeout)


def gen_public_key(
        public_key_path: str,
        private_key_path: str,
        private_key_password: str,
        subject: str,
        alt_subj_names: Optional[List[str]] = None,
        extended_key_usage: Optional[str] = None,
        validity_in_days: int = 365,
        timeout: int = 10,
        openssl: str = 'openssl',
) -> bool:
    """For a given private key, generates a corresponding public key."""
    with ssl_config(alt_subj_names, extended_key_usage) as (config_path, has_extension):
        command = [
            openssl, 'req', '-new', '-x509', '-sha256',
            '-days', str(validity_in_days), '-subj', subject,
            '-passin', 'pass:%s' % private_key_password,
            '-config', config_path,
            '-key', private_key_path, '-out', public_key_path,
        ]
        if has_extension:
            command.extend([
                '-extensions', 'PROXY',
            ])
        return run_openssl_command(command, timeout)


def gen_csr(
        csr_path: str,
        key_path: str,
        password: str,
        crt_path: str,
        timeout: int = 10,
        openssl: str = 'openssl',
) -> bool:
    """Generates a CSR based upon existing certificate and key file."""
    command = [
        openssl, 'x509', '-x509toreq',
        '-passin', 'pass:%s' % password,
        '-in', crt_path, '-signkey', key_path,
        '-out', csr_path,
    ]
    return run_openssl_command(command, timeout)


def sign_csr(
        csr_path: str,
        crt_path: str,
        ca_key_path: str,
        ca_key_password: str,
        ca_crt_path: str,
        serial: str,
        alt_subj_names: Optional[List[str]] = None,
        extended_key_usage: Optional[str] = None,
        validity_in_days: int = 365,
        timeout: int = 10,
        openssl: str = 'openssl',
) -> bool:
    """Sign a CSR using CA key and certificate."""
    with ext_file(alt_subj_names, extended_key_usage) as extension_path:
        command = [
            openssl, 'x509', '-req', '-sha256',
            '-CA', ca_crt_path,
            '-CAkey', ca_key_path,
            '-passin', 'pass:%s' % ca_key_password,
            '-set_serial', serial,
            '-days', str(validity_in_days),
            '-extfile', extension_path,
            '-in', csr_path,
            '-out', crt_path,
        ]
        return run_openssl_command(command, timeout)


def get_ext_config(
        alt_subj_names: Optional[List[str]] = None,
        extended_key_usage: Optional[str] = None,
) -> bytes:
    config = b''
    # Add SAN extension
    if alt_subj_names is not None and len(alt_subj_names) > 0:
        alt_names = []
        for cname in alt_subj_names:
            alt_names.append(b'DNS:%s' % bytes_(cname))
        config += b'\nsubjectAltName=' + COMMA.join(alt_names)
    # Add extendedKeyUsage section
    if extended_key_usage is not None:
        config += b'\nextendedKeyUsage=' + bytes_(extended_key_usage)
    return config


@contextlib.contextmanager
def ext_file(
        alt_subj_names: Optional[List[str]] = None,
        extended_key_usage: Optional[str] = None,
) -> Generator[str, None, None]:
    # Write config to temp file
    config_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex)
    with open(config_path, 'wb') as cnf:
        cnf.write(
            get_ext_config(alt_subj_names, extended_key_usage),
        )

    yield config_path

    # Delete temp file
    os.remove(config_path)


@contextlib.contextmanager
def ssl_config(
        alt_subj_names: Optional[List[str]] = None,
        extended_key_usage: Optional[str] = None,
) -> Generator[Tuple[str, bool], None, None]:
    config = DEFAULT_CONFIG

    has_extension = False
    if (alt_subj_names is not None and len(alt_subj_names) > 0) or \
            extended_key_usage is not None:
        has_extension = True
        config += b'\n[PROXY]'

    # Add custom extensions
    config += get_ext_config(alt_subj_names, extended_key_usage)

    # Write config to temp file
    config_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex)
    with open(config_path, 'wb') as cnf:
        cnf.write(config)

    yield config_path, has_extension

    # Delete temp file
    os.remove(config_path)


def run_openssl_command(command: List[str], timeout: int) -> bool:
    cmd = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cmd.communicate(timeout=timeout)
    return cmd.returncode == 0


if __name__ == '__main__':
    available_actions = (
        'remove_passphrase', 'gen_private_key', 'gen_public_key',
        'gen_csr', 'sign_csr',
    )

    parser = argparse.ArgumentParser(
        description='proxy.py v%s : PKI Utility' % __version__,
    )
    parser.add_argument(
        'action',
        type=str,
        default=None,
        help='Valid actions: ' + ', '.join(available_actions),
    )
    parser.add_argument(
        '--password',
        type=str,
        default='proxy.py',
        help='Password to use for encryption. Default: proxy.py',
    )
    parser.add_argument(
        '--private-key-path',
        type=str,
        default=None,
        help='Private key path',
    )
    parser.add_argument(
        '--public-key-path',
        type=str,
        default=None,
        help='Public key path',
    )
    parser.add_argument(
        '--subject',
        type=str,
        default='/CN=localhost',
        help='Subject to use for public key generation. Default: /CN=localhost',
    )
    parser.add_argument(
        '--csr-path',
        type=str,
        default=None,
        help='CSR file path.  Use with gen_csr and sign_csr action.',
    )
    parser.add_argument(
        '--crt-path',
        type=str,
        default=None,
        help='Signed certificate path.  Use with sign_csr action.',
    )
    parser.add_argument(
        '--hostname',
        type=str,
        default=None,
        help='Alternative subject names to use during CSR signing.',
    )
    parser.add_argument(
        '--openssl',
        type=str,
        default='openssl',
        help='Path to openssl binary.  By default, we assume openssl is in your PATH',
    )
    args = parser.parse_args(sys.argv[1:])

    # Validation
    if args.action not in available_actions:
        logger.error(
            'Invalid --action. Valid values ' +
            ', '.join(available_actions),
        )
        sys.exit(1)
    if args.action in ('gen_private_key', 'gen_public_key') and \
            args.private_key_path is None:
        logger.error('--private-key-path is required for ' + args.action)
        sys.exit(1)
    if args.action == 'gen_public_key' and \
            args.public_key_path is None:
        logger.error(
            '--public-key-file is required for private key generation',
        )
        sys.exit(1)

    # Execute
    if args.action == 'gen_private_key':
        gen_private_key(
            args.private_key_path,
            args.password, openssl=args.openssl,
        )
    elif args.action == 'gen_public_key':
        gen_public_key(
            args.public_key_path, args.private_key_path,
            args.password, args.subject, openssl=args.openssl,
        )
    elif args.action == 'remove_passphrase':
        remove_passphrase(
            args.private_key_path, args.password,
            args.private_key_path, openssl=args.openssl,
        )
    elif args.action == 'gen_csr':
        gen_csr(
            args.csr_path,
            args.private_key_path,
            args.password,
            args.public_key_path,
            openssl=args.openssl,
        )
    elif args.action == 'sign_csr':
        sign_csr(
            args.csr_path, args.crt_path, args.private_key_path, args.password,
            args.public_key_path, str(int(time.time())), alt_subj_names=[args.hostname],
            openssl=args.openssl,
        )
