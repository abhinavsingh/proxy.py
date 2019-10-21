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

if os.name != 'nt':
    import resource

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')


def get_temp_file(name: str) -> str:
    return os.path.join(tempfile.gettempdir(), name)


def get_available_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
        return int(port)


def get_plugin_by_test_name(test_name: str) -> Type[proxy.HttpProxyBasePlugin]:
    plugin: Type[proxy.HttpProxyBasePlugin] = plugin_examples.ModifyPostDataPlugin
    if test_name == 'test_modify_post_data_plugin':
        plugin = plugin_examples.ModifyPostDataPlugin
    elif test_name == 'test_proposed_rest_api_plugin':
        plugin = plugin_examples.ProposedRestApiPlugin
    elif test_name == 'test_redirect_to_custom_server_plugin':
        plugin = plugin_examples.RedirectToCustomServerPlugin
    elif test_name == 'test_filter_by_upstream_host_plugin':
        plugin = plugin_examples.FilterByUpstreamHostPlugin
    elif test_name == 'test_cache_responses_plugin':
        plugin = plugin_examples.CacheResponsesPlugin
    elif test_name == 'test_man_in_the_middle_plugin':
        plugin = plugin_examples.ManInTheMiddlePlugin
    return plugin


if __name__ == '__main__':
    proxy.UNDER_TEST = True
    unittest.main()
