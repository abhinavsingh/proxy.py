# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from setuptools import setup, find_packages

VERSION = (2, 2, 1)
__version__ = '.'.join(map(str, VERSION[0:3]))
__description__ = '''⚡⚡⚡Fast, Lightweight, Pluggable, TLS interception capable proxy server
    focused on Network monitoring, controls & Application development, testing, debugging.'''
__author__ = 'Abhinav Singh'
__author_email__ = 'mailsforabhinav@gmail.com'
__homepage__ = 'https://github.com/abhinavsingh/proxy.py'
__download_url__ = '%s/archive/master.zip' % __homepage__
__license__ = 'BSD'

if __name__ == '__main__':
    setup(
        name='proxy.py',
        version=__version__,
        author=__author__,
        author_email=__author_email__,
        url=__homepage__,
        description=__description__,
        long_description=open(
            'README.md', 'r', encoding='utf-8').read().strip(),
        long_description_content_type='text/markdown',
        download_url=__download_url__,
        license=__license__,
        python_requires='!=2.*, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*',
        zip_safe=False,
        packages=find_packages(exclude=['tests', 'tests.*']),
        package_data={'proxy': ['py.typed']},
        install_requires=open('requirements.txt', 'r').read().strip().split(),
        entry_points={
            'console_scripts': [
                'proxy = proxy:entry_point'
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
        keywords=(
            'http, proxy, http proxy server, proxy server, http server,'
            'http web server, proxy framework, web framework, Python3'
        )
    )
