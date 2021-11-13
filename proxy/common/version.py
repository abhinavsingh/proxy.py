# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Tuple, Union

from ._version import __version__  # noqa: WPS436


def _to_int_or_str(inp: str) -> Union[int, str]:
    try:
        return int(inp)
    except ValueError:
        return inp


def _split_version_parts(inp: str) -> Tuple[str, ...]:
    public_version, _plus, local_version = inp.partition('+')
    return (*public_version.split('.'), local_version)


VERSION = tuple(map(_to_int_or_str, _split_version_parts(__version__)))


__all__ = '__version__', 'VERSION'
