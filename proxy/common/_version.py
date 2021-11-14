# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    Version definition.
"""
try:
    # pylint: disable=unused-import
    from ._scm_version import version as __version__  # noqa: WPS433, WPS436
except ImportError:
    from pkg_resources import get_distribution as _get_dist  # noqa: WPS433
    __version__ = _get_dist('proxy.py').version  # noqa: WPS440


__all__ = ('__version__',)
