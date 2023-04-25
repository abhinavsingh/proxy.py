# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       auth
       http
       ldap
"""
import base64
from time import time
from typing import Dict, Optional

import ldap

from ..http import httpHeaders
from ..http.proxy import HttpProxyBasePlugin
from ..common.flag import flags
from ..http.parser import HttpParser
from ..http.exception import ProxyAuthenticationFailed


DEFAULT_LDAP_SERVER = 'ldap://ldap.example.org'
DEFAULT_LDAP_ROOT_DN = 'uid=Manager,ou=People,dc=example,dc=com'
DEFAULT_LDAP_ROOT_PW = 'SecretPassword'
DEFAULT_LDAP_BASE_DN = 'ou=People,dc=example,dc=com'
DEFAULT_LDAP_USER_SEARCH = '(&(uid={user})(accountStatus=active))'
DEFAULT_LDAP_AUTH_TIMEOUT = 3600

flags.add_argument(
    '--ldap-server',
    type=str,
    default=DEFAULT_LDAP_SERVER,
    help='Default: ' + DEFAULT_LDAP_SERVER +
    '.  LDAP server address.',
)

flags.add_argument(
    '--ldap-root-dn',
    type=str,
    default=DEFAULT_LDAP_ROOT_DN,
    help='Default: ' + DEFAULT_LDAP_ROOT_DN +
    '.  LDAP root dn.',
)

flags.add_argument(
    '--ldap-root-pw',
    type=str,
    default=DEFAULT_LDAP_ROOT_PW,
    help='Default: ' + DEFAULT_LDAP_ROOT_PW +
    '.  LDAP root password.',
)

flags.add_argument(
    '--ldap-base-dn',
    type=str,
    default=DEFAULT_LDAP_BASE_DN,
    help='Default: ' + DEFAULT_LDAP_BASE_DN +
    '.  LDAP users base DN.',
)

flags.add_argument(
    '--ldap-user-search',
    type=str,
    default=DEFAULT_LDAP_USER_SEARCH,
    help='Default: ' + DEFAULT_LDAP_USER_SEARCH +
    '.  LDAP user search filter.',
)

flags.add_argument(
    '--ldap-auth-timeout',
    type=int,
    default=DEFAULT_LDAP_AUTH_TIMEOUT,
    help='Default: ' + str(DEFAULT_LDAP_AUTH_TIMEOUT) +
    '.  LDAP user auth timeout.',
)


class LDAPAuthPlugin(HttpProxyBasePlugin):
    """Performs proxy authentication through LDAP."""

    __auth_pass__: Dict[bytes, float] = {}

    def auth_user(self, user: str, password: str) -> bool:
        ldap_connection = ldap.initialize(self.flags.ldap_server)
        ldap_connection.bind_s(self.flags.ldap_root_dn, self.flags.ldap_root_pw)
        search_filter = self.flags.ldap_user_search.format(user=user)
        search_result = ldap_connection.search_s(self.flags.ldap_base_dn, ldap.SCOPE_SUBTREE, search_filter, ['uid'])
        if len(search_result) != 1 and len(search_result[0]) != 2:
            return False
        try:
            ldap_connection.bind_s(search_result[0][0], password)
        except ldap.LDAPError:
            return False
        return True

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if not request.headers or httpHeaders.PROXY_AUTHORIZATION not in request.headers:
            raise ProxyAuthenticationFailed()
        parts = request.headers[httpHeaders.PROXY_AUTHORIZATION][1].split()
        if len(parts) != 2 or parts[0].lower() != b'basic':
            raise ProxyAuthenticationFailed()
        elif self.__auth_pass__.get(parts[1], 0) > time():
            return request
        elif self.__auth_pass__.get(parts[1], 0) < time():
            userpass = base64.b64decode(parts[1]).decode().split(':')
            user = userpass[0]
            password = userpass[-1]
            if self.auth_user(user, password):
                self.__auth_pass__[parts[1]] = time() + self.flags.ldap_auth_timeout
                return request
        raise ProxyAuthenticationFailed()
