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

import datetime
import errno
import io
import itertools
import logging
import os
import threading

import dropbox

from dropboxfs.path_common import Path

log = logging.getLogger(__name__)

def _md_to_stat(md):
    class _StatObject(object): pass
    toret = _StatObject()
    toret.name = md['path'].rsplit("/", 1)[1]
    toret.type = 'directory' if md['is_dir'] else 'file'
    toret.size = md['bytes']
    toret.mtime = (datetime.datetime.strptime(md['client_mtime'],
                                              "%a, %d %b %Y %H:%M:%S %z").astimezone()
                   if 'client_mtime' in md else
                   datetime.datetime.now())
    return toret

class _Directory(object):
    def __init__(self, fs, path):
        self._fs = fs
        self._path = path
        self.reset()

    def read(self):
        try:
            return next(self)
        except StopIteration:
            return None

    def reset(self):
        contents = self._fs._client.metadata(str(self._path))["contents"]
        log.debug("Contents for %r: %r", self._path, contents)
        self._md = iter(map(_md_to_stat, contents))

    def close(self):
        pass

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._md)

class _File(io.RawIOBase):
    def __init__(self, fs, path, md):
        self._fs = fs
        self._path = path
        self._offset = 0
        self._md = md

    def pread(self, offset, size=-1):
        with self._fs._client.get_file(str(self._path), start=offset,
                                       length=size if size >= 0 else None) as resp:
            return resp.read()

    def read(self, size=-1):
        toret = self.pread(offset, size)
        self._offset += toret
        return toret

    def readall(self):
        return self.read()

class FileSystem(object):
    def __init__(self, access_token):
        self._access_token = access_token
        self._local = threading.local()

    def create_path(self, *args):
        return Path.root_path().join(*args)

    # NB: This is probably evil opaque magic
    @property
    def _client(self):
        toret = getattr(self._local, '_client', None)
        if toret is None:
            self._local._client = toret = dropbox.client.DropboxClient(self._access_token)
        return toret

    def _get_md(self, path):
        log.debug("GET %r", path)
        try:
            md = self._client.metadata(str(path), list=False)
        except dropbox.rest.ErrorResponse as e:
            if e.status == 404:
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
            else: raise
        log.debug("md: %r", md)
        return _md_to_stat(md)

    def open(self, path):
        # NB: Unlike traditional file systems,
        #     we don't return ENOENT if the file doesn't exists
        # TODO: watch filesystem with /delta to detect external moves
        #       and update local file objects with new path
        md = self._get_md(path)
        return _File(self, path, md)

    def open_directory(self, path):
        return _Directory(self, path)

    def stat_has_attr(self, attr):
        return attr in ["type", "size", "mtime"]

    def stat(self, path):
        return self._get_md(path)

    def fstat(self, fobj):
        if isinstance(fobj, _Directory):
            class _StatObject(object): pass
            st = _StatObject()
            st.type = "directory"
            st.size = 0
            st.mtime = datetime.datetime.now()
            return st
        else:
            return fobj._md
