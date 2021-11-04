# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import sys
import subprocess
from proxy.common.version import __version__ as lib_version

# This script ensures our versions never run out of sync.
#
# 1. TODO: Version is hardcoded in homebrew stable package
#    installer file, but it only needs to match with lib
#    versions if current git branch is master

# Version is also hardcoded in README.md flags section
readme_version_cmd = 'cat README.md | grep "proxy.py v" | tail -2 | head -1 | cut -d " " -f 2 | cut -c2-'
readme_version_output = subprocess.check_output(
    ['bash', '-c', readme_version_cmd],
)
readme_version = readme_version_output.decode().strip()

if readme_version != lib_version:
    print(
        'Version mismatch found. {0} (readme) vs {1} (lib).'.format(
            readme_version, lib_version,
        ),
    )
    sys.exit(1)
