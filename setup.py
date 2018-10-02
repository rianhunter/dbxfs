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

setup(
    name="dbxfs",
    description="A Dropbox backed file system",
    url='https://github.com/rianhunter/dbxfs',
    license="GPL3",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    packages=["dbxfs"],
    install_requires=[
        "dropbox>=3.38",
        "appdirs>=1.4,<2",
        "userspacefs",
        "block_tracing",
        "privy",
        "keyring>=15.1,<16",
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
