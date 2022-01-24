# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import argparse
from typing import TYPE_CHECKING


if TYPE_CHECKING:   # pragma: no cover
    from ...common.types import HostPort
    try:
        from paramiko.channel import Channel
    except ImportError:
        pass


class SshHttpProtocolHandler:
    """Handles incoming connections over forwarded SSH transport."""

    def __init__(self, flags: argparse.Namespace) -> None:
        self.flags = flags

    def on_connection(
            self,
            chan: 'Channel',
            origin: 'HostPort',
            server: 'HostPort',
    ) -> None:
        pass
