#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup
from jpki import __version__

if os.path.exists('README.md'):
    README = open('README.md').read()
else:
    README = ""

setup(
    name='PyJPKI',
    version=__version__,
    description="JPKI tools",
    long_description=README,
    url="https://github.com/hamano/python-jpki",
    author = "Tsukasa Hamano",
    author_email = "hamano@osstech.co.jp",
    entry_points="""
[console_scripts]
jpki = jpki.__main__:main
""",
    py_modules=['jpki'],
    install_requires=open('requirements.txt').readlines(),
    license="MIT",
    classifiers=[
        'Development Status :: 1 - Planning',
    ]
)
