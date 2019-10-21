# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import base64
import json
import logging
import multiprocessing
import os
import selectors
import socket
import ssl
import tempfile
import unittest
import uuid
from contextlib import closing
from typing import Dict, Optional, Tuple, Union, Any, cast, Type
from unittest import mock
from urllib import parse as urlparse

import plugin_examples
import proxy

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')



def get_available_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
        return int(port)


if __name__ == '__main__':
    proxy.UNDER_TEST = True
    unittest.main()
