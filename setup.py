#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
from ostdoc import __version__

setup(
    name='PyJPKI',
    version=__version__,
    description="JPKI tools",
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
