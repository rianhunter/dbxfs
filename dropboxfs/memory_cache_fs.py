import collections
import contextlib
import errno
import logging
import os
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

class _File(object):
    def __init__(self, fs, f, stat, path):
        self._fs = fs
        self._f = f
        self._stat = stat

        self._fs._open_files_by_id[self._stat.id] = self

    def __getattr__(self, name):
        return getattr(self._f, name)

    def close(self):
        self._f.close()
        with self._fs._md_cache_lock:
            del self._fs._open_files_by_id[self._stat.id]

class FileSystem(object):
    def __init__(self, fs):
        self._fs = fs
        self._md_cache = {}
        self._md_cache_entries = {}
        self._md_cache_lock = threading.Lock()
        self._open_files_by_id = {}

        # watch file system and clear cache on any changes
        root_path = self._fs.create_path()
        self._watch_stop = self._fs.create_db_style_watch(self._handle_changes)

    def close(self):
        self._watch_stop()

    def _handle_changes(self, changes):
        with self._md_cache_lock:
            if changes == "reset":
                self._md_cache = {}
                self._md_cache_entries = {}
                return

            for change in changes:
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

                    self._md_cache[path] = 'deleted'
                else:
                    try:
                        self._open_files_by_id[change.id]._stat = dbmd_to_stat(change)
                    except KeyError:
                        pass

                    try:
                        parent_entries = self._md_cache_entries[parent_path]
                    except KeyError:
                        pass
                    else:
                        add_to_parent_entries(parent_entries, name)

                    # clear whatever metadata we have on this file
                    try:
                        del self._md_cache[path]
                    except KeyError:
                        pass

    def create_path(self, *args):
        return self._fs.create_path(*args)

    def open(self, path):
        with self._md_cache_lock:
            stat = self._stat_unlocked(path)
            return _File(self, self._fs.open_by_id(stat.id, is_directory=stat.type == "directory"),
                         stat, path)

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

    root_path = fs.create_path()
    with contextlib.closing(fs.open_directory(root_path)) as dir_:
        for n in dir_:
            print(n)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
