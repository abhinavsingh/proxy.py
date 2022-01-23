# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import Any, Optional

from .constants import DEFAULT_LOG_FILE, DEFAULT_LOG_LEVEL, DEFAULT_LOG_FORMAT


SINGLE_CHAR_TO_LEVEL = {
    'D': 'DEBUG',
    'I': 'INFO',
    'W': 'WARNING',
    'E': 'ERROR',
    'C': 'CRITICAL',
}


def single_char_to_level(char: str) -> Any:
    return getattr(logging, SINGLE_CHAR_TO_LEVEL[char.upper()[0]])


class Logger:
    """Common logging utilities and setup."""

    @staticmethod
    def setup(
            log_file: Optional[str] = DEFAULT_LOG_FILE,
            log_level: str = DEFAULT_LOG_LEVEL,
            log_format: str = DEFAULT_LOG_FORMAT,
    ) -> None:
        if log_file:    # pragma: no cover
            logging.basicConfig(
                filename=log_file,
                filemode='a',
                level=single_char_to_level(log_level),
                format=log_format,
            )
        else:
            logging.basicConfig(
                level=single_char_to_level(log_level),
                format=log_format,
            )
