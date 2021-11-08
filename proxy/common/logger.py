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

from typing import Optional

from .constants import DEFAULT_LOG_FILE, DEFAULT_LOG_FORMAT, DEFAULT_LOG_LEVEL

SINGLE_CHAR_TO_LEVEL = {
    'D': 'DEBUG',
    'I': 'INFO',
    'W': 'WARNING',
    'E': 'ERROR',
    'C': 'CRITICAL',
}


class Logger:
    """Common logging utilities and setup."""

    @staticmethod
    def setup_logger(
            log_file: Optional[str] = DEFAULT_LOG_FILE,
            log_level: str = DEFAULT_LOG_LEVEL,
            log_format: str = DEFAULT_LOG_FORMAT,
    ) -> None:
        ll = getattr(logging, SINGLE_CHAR_TO_LEVEL[log_level.upper()[0]])
        if log_file:
            logging.basicConfig(
                filename=log_file,
                filemode='a',
                level=ll,
                format=log_format,
            )
        else:
            logging.basicConfig(level=ll, format=log_format)
