#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from distutils.core import setup

setup(name='aioarping',
    packages=['aioarping'],
    version='0.1.0',
    author='François Wautier',
    author_email='francois@wautier.eu',
    description='API for arping over a LAN with asyncio.',
    url='http://github.com/frawau/aioarping',
    download_url='http://github.com/frawau/aiolifx/archive/aioarping/0.1.0.tar.gz',  
    keywords = ['arp', 'mac address', 'presence', 'automation'], 
    license='MIT',
    install_requires=[
    "ipaddress",
    ],
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5'
    ])