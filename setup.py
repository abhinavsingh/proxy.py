# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from setuptools import setup, find_packages

from proxy.common.version import __version__
from proxy.common.constants import __author__, __author_email__, __homepage__, __description__, __download_url__, __license__

setup(
    name='proxy.py',
    version=__version__,
    author=__author__,
    author_email=__author_email__,
    url=__homepage__,
    description=__description__,
    long_description=open('README.md').read().strip(),
    long_description_content_type='text/markdown',
    download_url=__download_url__,
    license=__license__,
    packages=find_packages(exclude=['benchmark', 'tests', 'plugin_examples']),
    install_requires=open('requirements.txt', 'r').read().strip().split(),
    entry_points={
        'console_scripts': [
            'proxy = proxy.main:entry_point'
        ]
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Environment :: No Input/Output (Daemon)',
        'Environment :: Web Environment',
        'Environment :: MacOS X',
        'Environment :: Plugins',
        'Environment :: Win32 (MS Windows)',
        'Framework :: Robot Framework',
        'Framework :: Robot Framework :: Library',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: MacOS',
        'Operating System :: MacOS :: MacOS 9',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Unix',
        'Operating System :: Microsoft',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Microsoft :: Windows :: Windows 10',
        'Operating System :: Android',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Browsers',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: Scientific/Engineering :: Information Analysis',
        'Topic :: Software Development :: Debuggers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Firewalls',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Utilities',
        'Typing :: Typed',
    ],
)
