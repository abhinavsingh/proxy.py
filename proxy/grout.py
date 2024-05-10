# -*- coding: utf-8 -*-
"""
Copyright (c) 2010-present by Jaxl Innovations Private Limited.

All rights reserved.

Redistribution and use in source and binary forms,
with or without modification, is strictly prohibited.
"""

import os
import sys
import gzip
import json
import time
import socket
import getpass
import argparse
from typing import Any, Dict, Tuple, Optional, cast

from .http.codes import httpStatusCodes
from .http.client import client
from .http.methods import httpMethods
from .common.plugins import Plugins
from .common.version import __version__
from .common.constants import HTTPS_PROTO


def grout() -> None:  # noqa: C901
    default_grout_tld = os.environ.get('JAXL_DEFAULT_GROUT_TLD', 'jaxl.io')

    def _clear_line() -> None:
        print('\r' + ' ' * 60, end='', flush=True)

    def _env(scheme: bytes, host: bytes, port: int) -> Optional[Dict[str, Any]]:
        response = client(
            scheme=scheme,
            host=host,
            port=port,
            path=b'/env/',
            method=httpMethods.BIND,
            body='v={0}&u={1}&h={2}'.format(
                __version__,
                os.environ.get('USER', getpass.getuser()),
                socket.gethostname(),
            ).encode(),
        )
        if response:
            if (
                response.code is not None
                and int(response.code) == httpStatusCodes.OK
                and response.body is not None
            ):
                return cast(
                    Dict[str, Any],
                    json.loads(
                        (
                            gzip.decompress(response.body).decode()
                            if response.has_header(b'content-encoding')
                            and response.header(b'content-encoding') == b'gzip'
                            else response.body.decode()
                        ),
                    ),
                )
            if response.code is None:
                _clear_line()
                print('\r\033[91mUnable to fetch\033[0m', end='', flush=True)
            else:
                _clear_line()
                print(
                    '\r\033[91mError code {0}\033[0m'.format(
                        response.code.decode(),
                    ),
                    end='',
                    flush=True,
                )
        else:
            _clear_line()
            print('\r\033[91mUnable to connect\033[0m')
        return None

    def _parse() -> Tuple[str, int]:
        """Here we deduce registry host/port based upon input parameters."""
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('route', nargs='?', default=None)
        parser.add_argument('name', nargs='?', default=None)
        args, _remaining_args = parser.parse_known_args()
        grout_tld = default_grout_tld
        if args.name is not None and '.' in args.name:
            grout_tld = args.name.split('.', maxsplit=1)[1]
        grout_tld_parts = grout_tld.split(':')
        tld_host = grout_tld_parts[0]
        tld_port = 443
        if len(grout_tld_parts) > 1:
            tld_port = int(grout_tld_parts[1])
        return tld_host, tld_port

    tld_host, tld_port = _parse()
    env = None
    attempts = 0
    try:
        while True:
            env = _env(scheme=HTTPS_PROTO, host=tld_host.encode(), port=int(tld_port))
            attempts += 1
            if env is not None:
                print('\rStarting ...' + ' ' * 30 + '\r', end='', flush=True)
                break
            time.sleep(1)
            _clear_line()
            print(
                '\rWaiting for connection {0}'.format('.' * (attempts % 4)),
                end='',
                flush=True,
            )
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(1)

    assert env is not None
    print('\r' + ' ' * 70 + '\r', end='', flush=True)
    Plugins.from_bytes(env['m'].encode(), name='client').grout(env=env['e'])  # type: ignore[attr-defined]
