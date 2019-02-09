# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    
    HTTP Proxy Server in Python.
    
    :copyright: (c) 2013-2018 by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
from setuptools import setup
import proxy

classifiers = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: No Input/Output (Daemon)',
    'Environment :: Web Environment',
    'Intended Audience :: Developers',
    'Intended Audience :: Education',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: BSD License',
    'Operating System :: MacOS',
    'Operating System :: MacOS :: MacOS 9',
    'Operating System :: MacOS :: MacOS X',
    'Operating System :: POSIX',
    'Operating System :: POSIX :: Linux',
    'Operating System :: Unix',
    'Operating System :: Microsoft',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.7',
    'Topic :: Internet :: Proxy Servers',
    'Topic :: Internet :: WWW/HTTP',
    'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: System :: Networking :: Monitoring',
    'Topic :: Utilities',
]

setup(
    name='proxy.py',
    version=proxy.__version__,
    author=proxy.__author__,
    author_email=proxy.__author_email__,
    url=proxy.__homepage__,
    description=proxy.__description__,
    long_description=open('README.md').read().strip(),
    download_url=proxy.__download_url__,
    classifiers=classifiers,
    license=proxy.__license__,
    py_modules=['proxy'],
    scripts=['proxy.py'],
    install_requires=[],
)
