# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       Cloudflare
       cloudflare
       dns
"""
import logging


try:
    import httpx
except ImportError:     # pragma: no cover
    pass

from typing import Tuple, Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.common.flag import flags
from proxy.common.types import HostPort


logger = logging.getLogger(__name__)


flags.add_argument(
    '--cloudflare-dns-mode',
    type=str,
    default='security',
    help='Default: security.  Either "security" (for malware protection) ' +
    'or "family" (for malware and adult content protection)',
)


class CloudflareDnsResolverPlugin(HttpProxyBasePlugin):
    """This plugin uses Cloudflare DNS resolver to provide protection
    against malware and adult content.  Implementation uses :term:`DoH`
    specification.

    See https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families
    See https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json

    .. note::

       For this plugin to work, make sure to bypass proxy for 1.1.1.1

    .. note::

       This plugin requires additional dependency because :term:`DoH`
       mandates a HTTP2 complaint client.  Install `httpx` dependency
       as::

           pip install "httpx[http2]"
    """

    def resolve_dns(self, host: str, port: int) -> Tuple[Optional[str], Optional[HostPort]]:
        try:
            context = httpx.create_ssl_context(http2=True)
            # TODO: Support resolution via Authority (SOA) to add support for
            # AAAA (IPv6) query
            r = httpx.get(
                'https://{0}.cloudflare-dns.com/dns-query?name={1}&type=A'.format(
                    self.flags.cloudflare_dns_mode, host,
                ),
                headers={'accept': 'application/dns-json'},
                verify=context,
                timeout=httpx.Timeout(timeout=5.0),
                proxies={
                    'all://': None,
                },
            )
            if r.status_code != 200:
                return None, None
            response = r.json()
            answers = response.get('Answer', [])
            if len(answers) == 0:
                return None, None
            # TODO: Utilize TTL to cache response locally
            # instead of making a DNS query repeatedly for the same host.
            return answers[0]['data'], None
        except Exception as e:
            logger.info(
                'Unable to resolve DNS-over-HTTPS for host {0} : {1}'.format(
                    host, str(e),
                ),
            )
            return None, None
