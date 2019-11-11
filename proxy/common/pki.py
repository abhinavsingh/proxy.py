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


def gen_private_key(
        key_path: str,
        password: str = 'proxy.py',
        bits: int = 2048,
        timeout: int = 10) -> bool:
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
        private_key_password: str = 'proxy.py',
        subject: str = '/C=US/ST=CA/L=SF/O=Proxy/OU=Eng/CN=proxy.py',
        validity_in_days: int = 365,
        timeout: int = 10) -> bool:
    """For a given private key, generates a corresponding public key."""
    with ssl_config(['proxy.py', 'www.proxy.py']) as config_path:
        command = [
            'openssl', 'req', '-new', '-x509', '-sha256',
            '-days', str(validity_in_days), '-subj', subject,
            '-passin', 'pass:%s' % private_key_password,
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


def gen_csr():
    pass


def sign_certificate():
    pass


DEFAULT_CONFIG = b'''[ req ]
#default_bits		= 2048
#default_md		= sha256
#default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_min			= 2
countryName_max			= 2
stateOrProvinceName		= State or Province Name (full name)
localityName			= Locality Name (eg, city)
0.organizationName		= Organization Name (eg, company)
organizationalUnitName		= Organizational Unit Name (eg, section)
commonName			= Common Name (eg, fully qualified host name)
commonName_max			= 64
emailAddress			= Email Address
emailAddress_max		= 64

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20'''


@contextlib.contextmanager
def ssl_config(
        cnames: List[str]) -> Generator[str, None, None]:
    config = DEFAULT_CONFIG

    # Add SAN extension
    alt_names = []
    for cname in cnames:
        alt_names.append(b'DNS:%s' % bytes_(cname))
    config += b'\n[SAN]\nsubjectAltName=' + COMMA.join(alt_names)

    # Write config to temp file
    config_path = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex)
    with open(config_path, 'wb') as cnf:
        cnf.write(config)

    yield config_path

    # Delete temp file
    os.remove(config_path)

# /usr/local/opt/openssl/bin/openssl genrsa -aes256 -passout pass:https -out https.key 2048
# /usr/local/opt/openssl/bin/openssl req -new -x509 -sha256 -days 365 -passin pass:https -key https.key
#   -out https.crt -reqexts SAN -config <(cat /etc/ssl/openssl.cnf
#       <(printf "\n[SAN]\nsubjectAltName=DNS:proxy.py,DNS:www.proxy.py\nextendedKeyUsage=serverAuth"))
# /usr/local/opt/openssl/bin/openssl req -out https.csr -key https.key -new
# /usr/local/opt/openssl/bin/openssl x509 -x509toreq -in https.crt -out https.csr -signkey https.key

# /usr/local/opt/openssl/bin/openssl genrsa -aes256 -passout pass:proxy-ca -out ca.key 2048
# /usr/local/opt/openssl/bin/openssl req -new -x509 -sha256 -days 365 -passin pass:proxy-ca -key ca.key -out ca.crt
# /usr/local/opt/openssl/bin/openssl x509 -req -days 365 -CA ca.crt -CAkey ca.key
#   -extfile <(printf "extendedKeyUsage = serverAuth \n subjectAltName=DNS:proxy.py,DNS:www.proxy.py")
#   -set_serial 123456789 -in https.csr -out https.crt

# /usr/local/opt/openssl/bin/openssl rsa -in https.key -out https-nopass.key
