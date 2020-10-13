"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import sys
from proxy.common.version import __version__ as lib_version
from setup import __version__ as pkg_version

# This script ensures our versions never run out of sync.
#
# 1. setup.py doesn't import proxy and hence they both use
#    their own respective __version__
# 2. TODO: Version is hardcoded in homebrew stable package
#    installer file, but it only needs to match with lib
#    versions if current git branch is master
# 3. TODO: Version is also hardcoded in README.md flags
#    section
if lib_version != pkg_version:
    print('Version mismatch found. {0} (lib) vs {1} (pkg).'.format(lib_version, pkg_version))
    sys.exit(1)
