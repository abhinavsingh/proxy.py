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
from typing import Any


class TlsInterceptionPropertyMixin:
    """A mixin which provides `tls_interception_enabled` property.

    This is mostly for use by core & external developer HTTP plugins.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.flags: argparse.Namespace = args[1]

    @property
    def tls_interception_enabled(self) -> bool:
        return self.flags.ca_key_file is not None and \
            self.flags.ca_cert_dir is not None and \
            self.flags.ca_signing_key_file is not None and \
            self.flags.ca_cert_file is not None
