#!/bin/sh
set -eu
rm -rf dist
python setup.py sdist bdist_wheel
twine upload dist/* --sign
