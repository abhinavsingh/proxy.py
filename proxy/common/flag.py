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
    """Wrapper around argparse module.

    proxy.py core and plugin classes must import `flag.flags` and
    use `add_argument` to define their own flags within respective
    class files.

    Best Practice:
    1. Define flags at the top of your class files.
    2. DO NOT add flags within your class `__init__` method OR
       within class methods.  It MAY result into runtime exception,
       especially if your class is initialized multiple times or if
       class method registering the flag gets invoked multiple times.
    """

    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            description='proxy.py v%s' % __version__,
            epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__
        )

    def add_argument(self, *args: Any, **kwargs: Any) -> None:
        """Register a flag."""
        self.parser.add_argument(*args, **kwargs)

    def parse_args(
            self, input_args: Optional[List[str]]) -> argparse.Namespace:
        """Parse flags from input arguments."""
        return self.parser.parse_args(input_args)


flags = FlagParser()
