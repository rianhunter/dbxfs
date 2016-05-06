import errno
import itertools
import logging
import os

from dropboxfs.memoryfs import FileSystem as MemoryFileSystem

log = logging.getLogger(__name__)

class QLDir(object):
    def __init__(self, *dirs):
        self._dirs = dirs
        self._curiter = self._myiter()

    def read(self):
        try:
            return next(self._curiter)
        except StopIteration:
            return None

    def readmany(self, size=None):
        if size is None:
            return list(self)
        else:
            return list(itertools.islice(self, size))

    def _myiter(self):
        for dir_ in self._dirs:
            yield from dir_

    def __iter__(self):
        return self._curiter

    def close(self):
        for dir_ in self._dirs:
            dir_.close()

class QLFile(object):
    def __init__(self, f):
        self._f = f

    def __getattr__(self, name):
        return getattr(self._f, name)

class FileSystem(object):
    def __init__(self, backing_fs):
        self._overlay  = MemoryFileSystem([(".ql_disablethumbnails", {"type": "file", "data": b""}),
                                           (".metadata_never_index", {"type": "file", "data": b""}),
                                           (".ql_disablecache", {"type": "file", "data": b""})])

        self._fs = backing_fs

    def _filter(self, path):
        if (path.name.startswith("._") or
            path.name.lower() == ".ds_store" or
            path == self.create_path(".TemporaryItems") or
            path == self.create_path(".Trashes")):
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        return path in [self.create_path(".ql_disablethumbnails"),
                        self.create_path(".metadata_never_index"),
                        self.create_path(".ql_disablecache")]

    def open(self, path, mode=os.O_RDONLY, directory=False):
        if self._filter(path):
            return QLFile(self._overlay.open(self._overlay.create_path(*path.parts[1:])))
        return self._fs.open(path, mode=mode, directory=directory)

    def open_directory(self, path):
        dir_ = self._fs.open_directory(path)
        if path == self.create_path():
            dir_ = QLDir(self._overlay.open_directory(path), dir_)
        return dir_

    def stat(self, path):
        if self._filter(path):
            return self._overlay.stat(self._overlay.create_path(*path.parts[1:]))
        return self._fs.stat(path)

    def fstat(self, fobj):
        if isinstance(fobj, QLFile):
            return self._overlay.fstat(fobj._f)
        return self._fs.fstat(fobj)

    def __getattr__(self, name):
        return getattr(self._fs, name)

