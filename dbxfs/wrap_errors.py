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

import functools
import logging
import io
import os

log = logging.getLogger(__name__)

def _cw(fn, *n, **kw):
    try:
        return fn(*n, **kw)
    except OSError:
        raise
    except Exception:
        log.exception("failed method: %r" % (fn, getattr(fn, '__name__', None),))
        raise

class WrapMethodMixin(object):
    def __getattr__(self, name):
        ret = getattr(self._sub, name)
        if callable(ret):
            @functools.wraps(ret)
            def newf(*n, **kw):
                return _cw(ret, *n, **kw)
            return newf
        return ret

    def _wrapped(self):
        return self._sub

class WrappedGeneral(WrapMethodMixin):
    def __init__(self, sub):
        self._sub = sub

    def __iter__(self):
        return _cw(iter, self._sub)

class FileSystem(WrapMethodMixin):
    def __init__(self, backing_fs):
        self._sub = backing_fs

    def open(self, *n, **kw):
        return WrappedGeneral(self._sub.open(*n, **kw))

    def open_directory(self, *n, **kw):
        return WrappedGeneral(self._sub.open_directory(*n, **kw))

    def create_watch(self, cb, handle, *n, **kw):
        return _cw(self._sub.create_watch, cb, handle._wrapped(), *n, **kw)

    def fsync(self, fobj):
        return _cw(self._sub.fsync, fobj._wrapped())

    def fstat(self, fobj):
        return _cw(self._sub.fstat, fobj._wrapped())

    def pwrite(self, handle, data, offset):
        return _cw(self._sub.pwrite, handle._wrapped(), data, offset)

    def pread(self, handle, size, offset):
        return _cw(self._sub.pread, handle._wrapped(), size, offset)

    def ftruncate(self, handle, offset):
        return _cw(self._sub.ftruncate, handle._wrapped(), offset)

    def close(self):
        self._sub.close()
