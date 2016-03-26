import collections
import contextlib
import errno
import io
import itertools
import logging
import os
import tempfile
import threading
import sys

from dropboxfs.path_common import file_name_norm
from dropboxfs.dbfs import md_to_stat as dbmd_to_stat

import dropbox

log = logging.getLogger(__name__)

class attr_merge(object):
    def __init__(self, *n):
        for obj in n:
            for name in dir(obj):
                if name.startswith("__") or name.startswith("_"):
                    continue
                setattr(self, name, getattr(obj, name))

    def __repr__(self):
        return 'attr_merge(' + ', '.join('%s=%r' % (k, getattr(self, k)) for k in dir(self)
                                         if not (k.startswith("__") and k.startswith("_"))) + ')'

Name = collections.namedtuple('Name', ['name'])
def md_plus_name(name, md):
    return attr_merge(Name(name), md)

class _Directory(object):
    def __init__(self, fs, path):
        with fs._md_cache_lock:
            to_iter = []

            try:
                entries_names = fs._md_cache_entries[path]
            except KeyError:
                # NB: THIS SLOWS DOWN MD_CACHE_LOCK
                # TODO: do mvcc by watching FS at the same time we pull directory info
                entries_names = []
                with contextlib.closing(fs._fs.open_directory(path)) as dir_:
                    for entry in dir_:
                        entries_names.append(entry.name)
                        to_iter.append(entry)
                        # NB: ordinarily, by the time we iterate this directory,
                        #     it could have been moved and these cache entries
                        #     will be wrong.  the directory interface allows for
                        #     any kind of consistency.  with the following code,
                        #     however, we exploit the fact that
                        #     dbfs.FileSystem._Directory is based on path,
                        #     rather than inode.  i.e. if we move the directory,
                        #     the directory handle will still return entries
                        #     under the original path it was opened with.
                        fs._md_cache[path / entry.name] = attr_merge(fs._md_cache.get(path / entry.name, object()), entry)
                fs._md_cache_entries[path] = entries_names
            else:
                for entry_name in entries_names:
                    md = fs._stat_unlocked(path / entry_name)
                    to_iter.append(md_plus_name(entry_name, md))

            self._it = iter(to_iter)

    def read(self):
        try:
            return next(self._it)
        except StopIteration:
            return None

    def readmany(self, size=None):
        if size is None:
            return list(self)
        else:
            return list(itertools.islice(self, size))

    def close(self):
        pass

    def __iter__(self):
        return self._it

# NB: YES these are linear, saving complex data-structure for later

def add_to_parent_entries(parent_entries, name):
    remove_from_parent_entries(parent_entries, name)
    parent_entries.append(name)

def remove_from_parent_entries(parent_entries, name):
    for (i, n) in enumerate(parent_entries):
        if file_name_norm(n) == file_name_norm(name):
            del parent_entries[i]
            break

class CachedFile(object):
    def __init__(self, fs, id_):
        self.fs = fs
        self.id = id_
        self.tempfile = tempfile.TemporaryFile()
        self.cond = threading.Condition()

        self._reset()

    def _reset(self):
        stop_signal = threading.Event()

        # start thread to stream file in
        def stream_file():
            with contextlib.closing(self.fs.open_by_id(self.id)) as f:
                self.tempfile.seek(0)
                while not stop_signal.is_set():
                    buf = f.read(2 ** 16)
                    if not buf: break
                    self.tempfile.write(buf)
                    self.tempfile.flush()
                    with self.cond:
                        self.stored += len(buf)
                        self.cond.notify_all()
                self.tempfile.truncate()
                with self.cond:
                    self.eof = self.stored
                    self.cond.notify_all()

        with self.cond:
            self.stored = 0
            self.eof = None

        self.stop_signal = stop_signal
        self.thread = threading.Thread(target=stream_file, daemon=True)
        self.thread.start()

    def reset(self):
        self.stop_signal.set()
        self.thread.join()
        self._reset()

    def _wait_for_range(self, offset, size):
        with self.cond:
            while (self.stored < offset + size and self.eof is None):
                self.cond.wait()

    def pread(self, offset, size):
        self._wait_for_range(offset, size)
        # TODO: port to windows, can use ReadFile
        return os.pread(self.tempfile.fileno(), size, offset)

    def close(self):
        self.stop_signal.set()
        self.thread.join()
        self.tempfile.close()

class _File(io.RawIOBase):
    def __init__(self, fs, stat, path):
        self._fs = fs
        self._stat = stat

        if self._stat.id not in self._fs._open_files_by_id:
            self._fs._open_files_by_id[self._stat.id] = set()

        self._fs._open_files_by_id[self._stat.id].add(self)

        if self._stat.type == "file":
            if self._stat.id not in self._fs._file_cache_by_id:
                self._fs._file_cache_by_id[self._stat.id] = CachedFile(self._fs._fs, stat.id)

            self._cached_file = self._fs._file_cache_by_id[self._stat.id]
        else:
            self._cached_file = None

        self._lock = threading.Lock()
        self._offset = 0

    def pread(self, offset, size):
        if self._cached_file is None:
            raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))
        return self._cached_file.pread(offset, size)

    def readinto(self, ibuf):
        with self._lock:
            obuf = self.pread(self._offset, len(ibuf))
            ibuf[:len(obuf)] = obuf
            self._offset += len(obuf)
            return len(obuf)

    def readable(self):
        return True

    def close(self):
        with self._fs._md_cache_lock:
            self._fs._open_files_by_id[self._stat.id].remove(self)
            if not self._fs._open_files_by_id[self._stat.id]:
                del self._fs._open_files_by_id[self._stat.id]

class FileSystem(object):
    def __init__(self, fs):
        self._fs = fs
        self._md_cache = {}
        self._md_cache_entries = {}
        self._md_cache_lock = threading.Lock()
        self._open_files_by_id = {}
        self._file_cache_by_id = {}

        # watch file system and clear cache on any changes
        # NB: we need to use a 'db style' watch because we need the
        #     ids, and create_watch() doesn't promise ids
        root_path = self._fs.create_path()
        self._watch_stop = self._fs.create_db_style_watch(self._handle_changes)

    def close(self):
        self._watch_stop()

    def _handle_changes(self, changes):
        with self._md_cache_lock:
            if changes == "reset":
                self._md_cache = {}
                self._md_cache_entries = {}

                todel = []
                for (id_, cached_file) in self._file_cache_by_id.items():
                    if id_ in self._open_files_by_id:
                        # Reset cached file if it's currently open
                        cached_file.reset()
                    else:
                        # Otherwise drop the cached file
                        todel.append(id_)

                for id_ in todel:
                    self._file_cache_by_id[id_].pop().close()

                return

            for change in changes:
                # NB: the metadata we currently have could be newer than this change
                #     the file will temporarily revert while we catch up to the newer state
                # TODO: don't process stale data, need 'server_modified' on all metadata
                #       entries from the dropbox api

                parent_path_str = "/" if change.path_lower.count("/") == 1 else change.path_lower[:change.path_lower.rfind("/")]
                parent_path = self.create_path(*([] if parent_path_str == "/" else parent_path_str[1:].split("/")))
                name = change.name
                path = parent_path / name
                if isinstance(change, dropbox.files.DeletedMetadata):
                    try:
                        parent_entries = self._md_cache_entries[parent_path]
                    except KeyError:
                        pass
                    else:
                        remove_from_parent_entries(parent_entries, name)

                    if path in self._md_cache:
                        self._md_cache[path] = 'deleted'
                else:
                    try:
                        for f in self._open_files_by_id[change.id]:
                            f._stat = dbmd_to_stat(change)
                    except KeyError:
                        # no open file with this id,
                        # so dump the cached file if it exists
                        try:
                            self._file_cache_by_id[change.id].close()
                            del self._file_cache_by_id[change.id]
                        except KeyError:
                            pass
                    else:
                        # we have some open files so reset the cached file
                        self._file_cache_by_id[change.id].reset()

                    try:
                        parent_entries = self._md_cache_entries[parent_path]
                    except KeyError:
                        pass
                    else:
                        add_to_parent_entries(parent_entries, name)

                    # update the metadata we have on this file
                    if path in self._md_cache:
                        self._md_cache[path] = dbmd_to_stat(change)

    def create_path(self, *args):
        return self._fs.create_path(*args)

    def open(self, path):
        with self._md_cache_lock:
            stat = self._stat_unlocked(path)
            return _File(self, stat, path)

    def open_directory(self, path):
        return _Directory(self, path)

    def stat_has_attr(self, attr):
        return self._fs.stat_has_attr(attr)

    def _stat_unlocked(self, path):
        try:
            stat = self._md_cache[path]
        except KeyError:
            # NB: Potentially slow!
            # TODO: do mvcc before storing back in md_cache
            try:
                stat = self._fs.stat(path)
            except FileNotFoundError:
                stat = 'deleted'
            self._md_cache[path] = stat
        if stat == 'deleted':
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        return stat

    def stat(self, path):
        with self._md_cache_lock:
            return self._stat_unlocked(path)

    def fstat(self, fobj):
        with self._md_cache_lock:
            return fobj._stat

    def create_watch(self, cb, handle, *n, **kw):
        return self._fs.create_watch(cb, handle._f, *n, **kw)

def main(argv):
    logging.basicConfig(level=logging.DEBUG)

    # This runtime import is okay because it happens in main()
    from dropboxfs.memoryfs import FileSystem as MemoryFileSystem

    backing_fs = MemoryFileSystem([("foo", {"type": "directory",
                                            "children" : [
                                                ("baz", {"type": "file", "data": b"YOOOO"}),
                                                ("quux", {"type": "directory"}),
                                            ]
                                        }),
                                   ("bar", {"type": "file", "data": b"f"})])
    fs = FileSystem(backing_fs)


    # Test Directory listing
    def list_fs(fs):
        print("Complete File Listing:")
        q = [fs.create_path()]
        while q:
            path = q.pop()

            stat = fs.stat(path)
            print(path, stat.type)

            with contextlib.closing(fs.open(path)) as f:
                try:
                    data = f.read()
                except IsADirectoryError:
                    assert stat.type == "directory"
                else:
                    assert stat.type == "file"
                    print(" Contents:", data)

            try:
                dir_handle = fs.open_directory(path)
            except NotADirectoryError:
                assert stat.type != "directory"
            else:
                assert stat.type == "directory"
                with contextlib.closing(dir_handle) as dir_:
                    for n in dir_:
                        q.append(path.joinpath(n.name))

    list_fs(fs)

    # Do it again to test caching
    list_fs(fs)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
