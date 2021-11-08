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
import abc
import logging
import inspect
import importlib

from typing import Any, List, Optional, Dict, Union

from .utils import bytes_, text_
from .constants import DOT, DEFAULT_ABC_PLUGINS

logger = logging.getLogger(__name__)


class Plugins:

    @staticmethod
    def discover(input_args: List[str]) -> None:
        """Search for plugin and plugins flag in command line arguments,
        then iterates over each value and discovers the plugin.
        """
        for i, f in enumerate(input_args):
            if f in ('--plugin', '--plugins'):
                v = input_args[i + 1]
                parts = v.split(',')
                for part in parts:
                    Plugins.importer(bytes_(part))

    @staticmethod
    def load(
        plugins: List[Union[bytes, type]],
        abc_plugins: List[str] = DEFAULT_ABC_PLUGINS,
    ) -> Dict[bytes, List[type]]:
        """Accepts a list Python modules, scans them to identify
        if they are an implementation of abstract plugin classes and
        returns a dictionary of matching plugins for each abstract class.
        """
        p: Dict[bytes, List[type]] = {}
        for abc_plugin in abc_plugins:
            p[bytes_(abc_plugin)] = []
        for plugin_ in plugins:
            klass, module_name = Plugins.importer(plugin_)
            assert klass and module_name
            mro = list(inspect.getmro(klass))
            mro.reverse()
            iterator = iter(mro)
            while next(iterator) is not abc.ABC:
                pass
            base_klass = next(iterator)
            if klass not in p[bytes_(base_klass.__name__)]:
                p[bytes_(base_klass.__name__)].append(klass)
            logger.info('Loaded plugin %s.%s', module_name, klass.__name__)
        return p

    @staticmethod
    def importer(plugin: Union[bytes, type]) -> Any:
        """Import and returns the plugin."""
        if isinstance(plugin, type):
            return (plugin, '__main__')
        plugin_ = text_(plugin.strip())
        assert plugin_ != ''
        module_name, klass_name = plugin_.rsplit(text_(DOT), 1)
        klass = getattr(
            importlib.import_module(
                module_name.replace(
                    os.path.sep, text_(DOT),
                ),
            ),
            klass_name,
        )
        return (klass, module_name)
