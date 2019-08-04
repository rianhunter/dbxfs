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

import errno
import os

from userspacefs.util_dumpster import IterableDirectory

# Dropbox doesn't allow the creation of some file names
# so we translate those names:

# desktop.ini
# thumbs.db
# .ds_store
# icon\r
# .dropbox
# .dropbox.attr
# starts with ~$
# starts with .~
# starts with ~ and ends with .tmp

# We use the unicode private use area to escape these file names
# Essentially this boils down to blocking a more rare prefix
# to allow more common characters

PREFIX = ".\ue052\ue041\ue048"

DISALLOWED_NAMES = frozenset([
    "desktop.ini",
    "thumbs.db",
    ".ds_store",
    "icon\r",
    ".dropbox",
    ".dropbox.attr",
])

def encode_name(p):
    if p.startswith(PREFIX):
        raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))
    plower = p.lower()
    if (plower.startswith("~") and plower.endswith(".tmp") or
        plower.startswith("~$") or
        plower.startswith(".~") or
        plower in DISALLOWED_NAMES):
        p = PREFIX + p
    return p

def decode_name(p):
    if p.startswith(PREFIX):
        p = p[len(PREFIX):]
    return p

class _Directory(IterableDirectory):
    def __init__(self, dir_):
        self._dir = dir_
        self._curiter = self._myiter()

    def _myiter(self):
        for entry in self._dir:
            yield entry._replace(name=decode_name(entry.name))

    def __iter__(self):
        return self._curiter

    def close(self):
        if self._dir is None:
            return
        self._dir.close()
        self._dir = None

class FileSystem(object):
    def __init__(self, backing_fs):
        self._sub = backing_fs

    def _convert_path(self, path):
        tocreate = []
        for p in path.parts[1:]:
                tocreate.append(encode_name(p))
        return self._sub.create_path(*tocreate)

    def open(self, path, *n, **kw):
        return self._sub.open(self._convert_path(path), *n, **kw)

    def open_directory(self, path, *n, **kw):
        return _Directory(self._sub.open_directory(self._convert_path(path), *n, **kw))

    def stat(self, path):
        return self._sub.stat(self._convert_path(path))

    def unlink(self, path):
        return self._sub.unlink(self._convert_path(path))

    def mkdir(self, path):
        return self._sub.mkdir(self._convert_path(path))

    def rmdir(self, path):
        return self._sub.rmdir(self._convert_path(path))

    def rename_noreplace(self, old_path, new_path):
        return self._sub.rename_noreplace(self._convert_path(old_path),
                                          self._convert_path(new_path))

    def create_watch(self, cb, *n, **kw):
        def newcb(entries):
            if entries == "reset":
                return cb(entries)

            toret = []
            for entry in entries:
                toret.append(
                    entry._replace(
                        path=[decode_name(p)
                              for p in entry.path]
                    )
                )

            return cb(toret)

        return self._sub.create_watch(newcb, *n, **kw)

    def __getattr__(self, name):
        return getattr(self._sub, name)
