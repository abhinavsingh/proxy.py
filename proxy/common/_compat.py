"""Compatibility code for using Proxy.py across various versions of Python.

.. spelling::

   compat
   py
"""

import platform


SYS_PLATFORM = platform.system()
IS_WINDOWS = SYS_PLATFORM == 'Windows'
