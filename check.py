# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
"""Performs various checks and optionally fixes them in-place."""
import sys
import subprocess

from pathlib import Path
from proxy.common.version import __version__ as lib_version

# This script ensures our versions never run out of sync.
#
# 1. TODO: Version is hardcoded in homebrew stable package
#    installer file, but it only needs to match with lib
#    versions if current git branch is master

PROXY_PY_PREFIX = ' •'.join([
    ' • '.join([
        '# ⚡ Fast',
        '🪶 Lightweight',
        '0️⃣ Dependency',
        '🔌 Pluggable',
    ]),
    ' • '.join([
        '\n# 😈 TLS interception',
        '🔒 DNS-over-HTTPS',
        '🔥 Poor Man\'s VPN',
    ]),
    ' • '.join([
        '\n# ⏪ Reverse & ⏩ Forward',
        '👮🏿 "Proxy Server" framework',
    ]),
    ' • '.join([
        '\n# 🌐 "Web Server" framework',
        '➵ ➶ ➷ ➠ "PubSub" framework',
    ]),
    '\n# 👷 "Work" acceptor & executor framework.',
])

PY_FILE_LICENSE_PREFIX = '\n'.join([
    '# -*- coding: utf-8 -*-',
    '#',
    '# proxy.py',
    '# ~~~~~~~~',
    PROXY_PY_PREFIX,
    '#',
    '# :copyright: (c) 2013-present by Abhinav Singh and contributors.',
    '# :license: BSD, see LICENSE for more details.',
]).encode('utf-8')

REPO_ROOT = Path(__file__).parent
ALL_PY_FILES = (
    list(REPO_ROOT.glob('*.py')) +
    list((REPO_ROOT / 'proxy').rglob('*.py')) +
    list((REPO_ROOT / 'examples').rglob('*.py')) +
    list((REPO_ROOT / 'tests').rglob('*.py'))
)

# Ensure all python files start with licensing information
for py_file in ALL_PY_FILES:
    if py_file.is_file() and py_file.name != '_scm_version.py':
        with open(py_file, 'rb') as f:
            code = f.read(len(PY_FILE_LICENSE_PREFIX))
            if code != PY_FILE_LICENSE_PREFIX:
                print(
                    'Expected license not found in {0}'.format(
                        str(py_file),
                    ),
                )
                sys.exit(1)

# Update README.md flags section to match current library --help output
# lib_help = subprocess.check_output(
#     ['python', '-m', 'proxy', '-h']
# )
# with open('README.md', 'rb+') as f:
#     c = f.read()
#     pre_flags, post_flags = c.split(b'# Flags')
#     help_text, post_changelog = post_flags.split(b'# Changelog')
#     f.seek(0)
#     f.write(pre_flags + b'# Flags\n\n```console\n\xe2\x9d\xaf proxy -h\n' + lib_help + b'```' +
#             b'\n# Changelog' + post_changelog)

# Version is also hardcoded in README.md flags section
readme_version_cmd = 'cat README.md | grep "proxy.py v" | tail -2 | head -1 | cut -d " " -f 2 | cut -c2-'
readme_version_output = subprocess.check_output(
    ['bash', '-c', readme_version_cmd],
)
# Doesn't contain "v" prefix
readme_version = readme_version_output.decode().strip()

if readme_version != lib_version:
    print(
        'Version mismatch found. {0} (readme) vs {1} (lib).'.format(
            readme_version, lib_version,
        ),
    )
    sys.exit(1)
