# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import inspect
import logging
import importlib
import itertools
from types import ModuleType
from typing import Any, Dict, List, Tuple, Union, Optional

from .utils import text_, bytes_
from .constants import DOT, COMMA, DEFAULT_ABC_PLUGINS


logger = logging.getLogger(__name__)


class Plugins:
    """Common utilities for plugin discovery."""

    @staticmethod
    def resolve_plugin_flag(flag_plugins: Any, opt_plugins: Optional[Any] = None) -> List[Union[bytes, type]]:
        if isinstance(flag_plugins, list):
            requested_plugins = list(
                itertools.chain.from_iterable([
                    p.split(text_(COMMA)) for p in list(
                        itertools.chain.from_iterable(flag_plugins),
                    )
                ]),
            )
        else:
            requested_plugins = flag_plugins.split(text_(COMMA))
        return [
            p if isinstance(p, type) else bytes_(p)
            for p in (opt_plugins if opt_plugins is not None else requested_plugins)
            if not (isinstance(p, str) and len(p) == 0)
        ]

    @staticmethod
    def discover(input_args: List[str]) -> None:
        """Search for external plugin found in command line arguments,
        then iterates over each value and discover/import the plugin.
        """
        for i, f in enumerate(input_args):
            if f in ('--plugin', '--plugins', '--auth-plugin'):
                v = input_args[i + 1]
                parts = v.split(',')
                for part in parts:
                    Plugins.importer(bytes_(part))

    @staticmethod
    def load(
        plugins: List[Union[bytes, type]],
        abc_plugins: Optional[List[str]] = None,
    ) -> Dict[bytes, List[type]]:
        """Accepts a list Python modules, scans them to identify
        if they are an implementation of abstract plugin classes and
        returns a dictionary of matching plugins for each abstract class.
        """
        p: Dict[bytes, List[type]] = {}
        for abc_plugin in (abc_plugins or DEFAULT_ABC_PLUGINS):
            p[bytes_(abc_plugin)] = []
        for plugin_ in plugins:
            klass, module_name = Plugins.importer(plugin_)
            assert klass and module_name
            mro = list(inspect.getmro(klass))
            # Find the base plugin class that
            # this plugin_ is implementing
            base_klass = None
            for k in mro:
                if bytes_(k.__name__) in p:
                    base_klass = k
                    break
            if base_klass is None:
                raise ValueError('%s is NOT a valid plugin' % text_(plugin_))
            if klass not in p[bytes_(base_klass.__name__)]:
                p[bytes_(base_klass.__name__)].append(klass)
            logger.info('Loaded plugin %s.%s', module_name, klass.__name__)
        # print(p)
        return p

    @staticmethod
    def importer(plugin: Union[bytes, type]) -> Tuple[type, str]:
        """Import and returns the plugin."""
        if isinstance(plugin, type):
            if inspect.isclass(plugin):
                return (plugin, plugin.__module__ or '__main__')
            raise ValueError('%s is not a valid reference to a plugin class' % text_(plugin))
        plugin_ = text_(plugin.strip())
        assert plugin_ != ''
        path = plugin_.split(text_(DOT))
        klass = None

        def locate_klass(klass_module_name: str, klass_path: List[str]) -> Union[type, None]:
            klass_module_name = klass_module_name.replace(os.path.sep, text_(DOT))
            try:
                klass_module = importlib.import_module(klass_module_name)
            except ModuleNotFoundError:
                return None
            klass_container: Union[ModuleType, type] = klass_module
            for klass_path_part in klass_path:
                try:
                    klass_container = getattr(klass_container, klass_path_part)
                except AttributeError:
                    return None
            if not isinstance(klass_container, type) or not inspect.isclass(klass_container):
                return None
            return klass_container

        module_name = None
        for module_name_parts in range(len(path) - 1, 0, -1):
            module_name = '.'.join(path[0:module_name_parts])
            klass = locate_klass(module_name, path[module_name_parts:])
            if klass:
                break
        if klass is None:
            module_name = '__main__'
            klass = locate_klass(module_name, path)
        if klass is None or module_name is None:
            raise ValueError('%s is not resolvable as a plugin class' % text_(plugin))
        return (klass, module_name)
