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
from typing import Optional, List, Any

from .version import __version__

__homepage__ = 'https://github.com/abhinavsingh/proxy.py'


class FlagParser:
    """An abstract container for defining command line flags.

    Unlike `flags.Flags` class, FlagParser class doesn't contain any pre-defined flags.
    proxy.py core and plugin classes must import flag.flags and call add_argument to
    define their own flags.
    """

    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            description='proxy.py v%s' % __version__,
            epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__
        )

    def add_argument(self, *args: Any, **kwargs: Any) -> None:
        self.parser.add_argument(*args, **kwargs)

    def parse_args(
            self, input_args: Optional[List[str]]) -> argparse.Namespace:
        return self.parser.parse_args(input_args)


flags = FlagParser()
