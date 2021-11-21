# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time

from typing import Any


class cached_property:
    """Decorator for read-only properties evaluated only once within TTL period.
    It can be used to create a cached property like this::

        import random

        # the class containing the property must be a new-style class
        class MyClass:
            # create property whose value is cached for ten minutes
            @cached_property(ttl=600)
            def randint(self):
                # will only be evaluated every 10 min. at maximum.
                return random.randint(0, 100)

    The value is cached  in the '_cached_properties' attribute of the object instance that
    has the property getter method wrapped by this decorator. The '_cached_properties'
    attribute value is a dictionary which has a key for every property of the
    object which is wrapped by this decorator. Each entry in the cache is
    created only when the property is accessed for the first time and is a
    two-element tuple with the last computed property value and the last time
    it was updated in seconds since the epoch.

    The default time-to-live (TTL) is 300 seconds (5 minutes). Set the TTL to
    zero for the cached value to never expire.

    To expire a cached property value manually just do::
        del instance._cached_properties[<property name>]

    Adopted from https://wiki.python.org/moin/PythonDecoratorLibrary#Cached_Properties
    © 2011 Christopher Arndt, MIT License.

    NOTE: We need this function only because Python in-built are only available
    for 3.8+.  Hence, we must get rid of this function once proxy.py no longer
    support version older than 3.8.

    .. spelling::

       backports
       getter
       Arndt
    """

    def __init__(self, ttl: float = 300.0):
        self.ttl = ttl

    def __call__(self, fget: Any, doc: Any = None) -> 'cached_property':
        self.fget = fget
        self.__doc__ = doc or fget.__doc__
        self.__name__ = fget.__name__
        self.__module__ = fget.__module__
        return self

    def __get__(self, inst: Any, owner: Any) -> Any:
        now = time.time()
        try:
            value, last_update = inst._cached_properties[self.__name__]
            if self.ttl > 0 and now - last_update > self.ttl:   # noqa: WPS333
                raise AttributeError
        except (KeyError, AttributeError):
            value = self.fget(inst)
            try:
                cache = inst._cached_properties
            except AttributeError:
                cache, inst._cached_properties = {}, {}
            finally:
                cache[self.__name__] = (value, now)
        return value
