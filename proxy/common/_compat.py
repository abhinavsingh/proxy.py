"""Compatibility code for using Proxy.py across various versions of Python."""

import platform


SYS_PLATFORM = platform.system()
IS_WINDOWS = SYS_PLATFORM == 'Windows'
