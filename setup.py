#!/usr/bin/env python3

# This file is part of dbxfs.

# dbxfs is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# dbxfs is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with dbxfs.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name="dbxfs",
    version='1.0.48',
    author="Rian Hunter",
    author_email="rian@alum.mit.edu",
    description="User-space file system for Dropbox",
    long_description=long_description,
    url='https://github.com/rianhunter/dbxfs',
    license="GPL3",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    packages=["dbxfs"],
    install_requires=[
        # dropbox changes so often that we
        # just put a lower bound to avoid
        # dbxfs being uninstallable in the future
        # if dropbox=11 goes away.
        "dropbox>=11",
        "appdirs>=1.4,<2",
        "userspacefs>=2.0.2,<3",
        "block_tracing>=1.0.1,<2",
        "privy>=6.0,<7",
        "keyring>=15.1.0",
        "keyrings.alt>=3.1,<5",
        "sentry_sdk>=0.3,<1",
    ],
    extras_require={
        'safefs': ["safefs"],
    },
    entry_points={
        'console_scripts': [
            "dbxfs=dbxfs.main:main",
        ],
    },
)
