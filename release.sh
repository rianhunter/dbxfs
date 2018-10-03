#!/bin/sh

if ! git diff-index --cached --quiet HEAD --ignore-submodules --
then
    echo "Uncommited changes in index!" >&2
    exit 1
fi

VERSION=$(cat setup.py | gawk 'match($0, /version *= *'"'"'([^'"'"']*)/, ary) {print ary[1]}')
if [ -z "$VERSION" ]
then
    VERSION=$(cat setup.py | gawk 'match($0, /version *= *"([^"]*)/, ary) {print ary[1]}')
fi

if [ -z "$VERSION" ]
then
    echo "Couldn't parse version!" >&2
fi

MAJOR=$(echo $VERSION | sed 's/\([0-9]\{1,\}\)\.[0-9]\{1,\}\.[0-9]\{1,\}/\1/')
MINOR=$(echo $VERSION | sed 's/[0-9]\{1,\}\.\([0-9]\{1,\}\)\.[0-9]\{1,\}/\1/')
PATCH=$(echo $VERSION | sed 's/[0-9]\{1,\}\.[0-9]\{1,\}\.\([0-9]\{1,\}\)/\1/')


level=0
while getopts ":Mmp" opt
do
    case $opt in
        M) level=2 ;;
        m) level=1 ;;
        p) level=0 ;;
    esac
done

case $level in
    0)
        PATCH=$((PATCH + 1))
        ;;
    1)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    2)
        MAJOR=$((MAJOR + 1));
        MINOR=0
        PATCH=0
        ;;
esac

VERSION=$MAJOR.$MINOR.$PATCH

echo $VERSION

cat setup.py | sed "s/version *= *'[^']*'/version='$VERSION'/" | sed "s/version *= *\"[^\"]*\"/version='$VERSION'/" > setup.py.new
mv setup.py.new setup.py

git add setup.py
git commit -m "Release $VERSION"
git tag -s v$VERSION -m "Signed $VERSION"
