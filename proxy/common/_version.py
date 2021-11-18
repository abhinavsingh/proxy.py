# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
"""
    Version definition.
"""
from typing import Tuple, Union

try:
    # pylint: disable=unused-import
    from ._scm_version import version as __version__, version_tuple as _ver_tup  # noqa: WPS433, WPS436
except ImportError:
    from pkg_resources import get_distribution as _get_dist  # noqa: WPS433
    __version__ = _get_dist('proxy.py').version  # noqa: WPS440


def _to_int_or_str(inp: str) -> Union[int, str]:
    try:
        return int(inp)
    except ValueError:
        return inp


def _split_version_parts(inp: str) -> Tuple[str, ...]:
    public_version, _plus, local_version = inp.partition('+')
    return (*public_version.split('.'), local_version)


try:
    VERSION = _ver_tup
except NameError:
    VERSION = tuple(
        map(_to_int_or_str, _split_version_parts(__version__)),
    )


__all__ = '__version__', 'VERSION'
