#!/usr/bin/env python3

# This file is part of dropboxfs.

# dropboxfs is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# dropboxfs is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with dropboxfs.  If not, see <http://www.gnu.org/licenses/>.

import collections
import ctypes
import errno
import io
import itertools
import logging
import os
import warnings

from datetime import datetime

from dropboxfs.path_common import Path

log = logging.getLogger(__name__)

def get_size(md):
    if md["type"] == "directory":
        return 0
    else:
        assert md["type"] == "file"
        return len(md.get("data", b''))

def get_children(md):
    assert md["type"] == "directory"
    return md.get("children", [])

class _File(io.RawIOBase):
    def __init__(self, md):
        self._md = md
        self._offset = 0

    def pread(self, offset, size=-1):
        if self._md["type"] == "directory":
            raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))
        return self._md["data"][offset:
                                len(self._md["data"]) if size < 0 else offset + size]

    def read(self, size=-1):
        a = self.pread(self._offset, size)
        self._offset += len(a)
        return a

    def readall(self):
        return self.read()

class _Directory(object):
    def __init__(self, fs, md):
        self._fs = fs
        self._md = md
        self.reset()

    def reset(self):
        # NB: I apologize if you're about to grep for _map_entry()
        self._iter = iter(map(lambda tup: self._fs._map_entry(tup[1], tup[0]), get_children(self._md)))

    def close(self):
        pass

    def read(self):
        try:
            return next(self)
        except StopIteration:
            return None

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter)

_Stat = collections.namedtuple("Stat", ['name', 'mtime', 'type', 'size', 'id', 'ctime'])

class FileSystem(object):
    def __init__(self, tree):
        self._mtime = datetime.utcnow()
        self._ctime = datetime.utcnow()
        self._parent = {"type": "directory",
                        "children": tree}

    def _map_entry(self, md, name=None):
        if 'mtime' in md:
            mtime = md['mtime']
        else:
            mtime = self._mtime

        if 'ctime' in md:
            ctime = md['ctime']
        else:
            ctime = self._ctime

        type = md["type"]
        size = get_size(md)

        return _Stat(name, mtime, type, size, id=id(md), ctime=ctime)

    def _get_file(self, path):
        parent = self._parent
        real_comps = []
        for comp in itertools.islice(path.parts, 1, None):
            if parent["type"] != "directory":
                parent = None
                break

            for (name, md) in get_children(parent):
                if name.lower() == comp.lower():
                    real_comps.append(name)
                    parent = md
                    break
            else:
                parent = None
                break

        if parent is None:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        return parent

    def parse_path(self, path):
        return Path.parse_path(path)

    def create_path(self, *args):
        return Path.root_path().joinpath(*args)

    def open(self, path):
        md = self._get_file(path)
        return _File(md)

    def open_by_id(self, id_):
        warnings.warn("Don't use this in production, could cause segfault if used with an invalid ID")
        # id is the memory address of the md object
        return _File(ctypes.cast(id_, ctypes.py_object).value)

    def open_directory(self, path):
        md = self._get_file(path)
        if md['type'] != "directory":
            raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))

        return _Directory(self, md)

    def stat_has_attr(self, attr):
        return attr in ["type", "name", "mtime"]

    def stat(self, path):
        return self._map_entry(self._get_file(path))

    def fstat(self, fobj):
        return self._map_entry(fobj._md)

    def create_watch(self, cb, dir_handle, completion_filter, watch_tree):
        if dir_handle._md['type'] != "directory":
            raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))

        # NB: current MemoryFS is read-only so
        #     just wait for stop() is a no-op and cb is never called

        def stop(): pass

        return stop

