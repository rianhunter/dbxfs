import _sqlite3
import collections
import contextlib
import ctypes
import datetime
import errno
import functools
import io
import itertools
import json
import logging
import os
import tempfile
import threading
import traceback
import shutil
import sqlite3
import sys
import weakref

from dropboxfs.path_common import file_name_norm
from dropboxfs.dbfs import md_to_stat as dbmd_to_stat
from dropboxfs.util_dumpster import utctimestamp

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

REQUIRED_ATTRS = ["mtime", "type", "size", "id", "ctime"]
Stat = collections.namedtuple("Stat", REQUIRED_ATTRS)

def stat_to_json(obj):
    toret = {}
    for name in REQUIRED_ATTRS:
        elt = getattr(obj, name, None)
        if elt is None: continue
        if name in ("mtime", "ctime"):
            elt = utctimestamp(elt)
        toret[name] = elt
    return json.dumps(toret)


def json_to_stat(str_):
    info = json.loads(str_)
    for name in REQUIRED_ATTRS:
        val = info.get(name)
        if val is None:
            info[name] = val
        elif name in ("mtime", "ctime"):
            val = datetime.datetime.utcfromtimestamp(val)
            info[name] = val
    return Stat(**info)

def attr_merge_sql(md_str_1, md_str_2):
    if md_str_1 is None:
        return md_str_2

    if md_str_2 is None:
        return md_str_1

    md1 = json_to_stat(md_str_1)
    md2 = json_to_stat(md_str_2)

    return stat_to_json(attr_merge(md1, md2))

def wrap_show_exc(fn):
    @functools.wraps(fn)
    def fn2(*n, **kw):
        try:
            return fn(*n, **kw)
        except:
            traceback.print_exc()
            raise
    return fn2

def file_name_norm_2(*n, **kw):
    return file_name_norm(*n, **kw)

_hold_ref_lock = threading.Lock()
_hold_ref = weakref.WeakKeyDictionary()
def register_deterministic_function(conn, name, num_params, func):
    if not isinstance(conn, sqlite3.Connection):
        raise Exception("Bad connection object: %r" % (conn,))

    # This is a hack, oh well this is how I roll
    # TODO: submit patch to pysqlite to do this natively

    if sys.platform == "darwin":
        RTLD_NOLOAD = 0x10
    elif sys.platform.startswith("linux"):
        RTLD_NOLOAD = 0x04
    else:
        raise Exception("Platform not supported!")

    pysqlite_dll = ctypes.PyDLL(_sqlite3.__file__, ctypes.RTLD_GLOBAL | RTLD_NOLOAD)

    sqlite3_create_function_proto = ctypes.CFUNCTYPE(ctypes.c_int,
                                                     ctypes.c_void_p, # db
                                                     ctypes.c_char_p, # zFunctionName
                                                     ctypes.c_int, # nArg
                                                     ctypes.c_int, # eTextRep
                                                     ctypes.c_void_p, # pApp
                                                     ctypes.c_void_p,
                                                     ctypes.c_void_p,
                                                     ctypes.c_void_p)

    sqlite3_create_function = sqlite3_create_function_proto(("sqlite3_create_function",
                                                             pysqlite_dll))

    # get dp pointer from connection object
    dbp = ctypes.cast(id(conn) +
                      ctypes.sizeof(ctypes.c_ssize_t) +
                      ctypes.sizeof(ctypes.c_void_p),
                      ctypes.POINTER(ctypes.c_void_p)).contents

    SQLITE_DETERMINISTIC = 0x800
    SQLITE_UTF8 = 0x1
    rc = sqlite3_create_function(dbp, name.encode("utf8"), num_params,
                                 SQLITE_DETERMINISTIC | SQLITE_UTF8,
                                 id(func),
                                 pysqlite_dll._pysqlite_func_callback,
                                 None,
                                 None)
    if rc:
        raise Exception("Error while creating function: %r" % (rc,))

    # hold ref on passed function object
    with _hold_ref_lock:
        if conn not in _hold_ref:
            _hold_ref[conn] = []
        _hold_ref[conn].append(func)

@contextlib.contextmanager
def null_context():
    yield

@contextlib.contextmanager
def trans(conn, lock, is_exclusive=False):
    # NB: This exists because pysqlite will not start a transaction
    # until it sees a DML statement. This sucks if we start a transaction
    # with a SELECT statement.
    with (null_context()
          if lock is None else
          lock
          if is_exclusive else
          lock.shared_context()):
        isolation_level = "IMMEDIATE" if is_exclusive else "DEFERRED"
        iso = conn.isolation_level
        conn.isolation_level = None
        conn.execute("BEGIN " + isolation_level)
        try:
            yield conn
        finally:
            conn.commit()
            conn.isolation_level = iso

EMPTY_DIR_ENT = "/empty/"

class WeakrefableConnection(sqlite3.Connection):
    pass

class _Directory(object):
    def __init__(self, fs, path):
        conn = fs._get_db_conn()
        with trans(conn, fs._db_lock, is_exclusive=True), contextlib.closing(conn.cursor()) as cursor:
            path_key = str(path.normed())

            cursor.execute("SELECT name, (SELECT md FROM md_cache WHERE path_key = norm_join(md_cache_entries.path_key, md_cache_entries.name)) FROM md_cache_entries WHERE path_key = ?",
                           (path_key,))

            is_empty = False
            to_iter = []
            for (name, md_str) in cursor:
                if name == EMPTY_DIR_ENT:
                    is_empty = True
                    break
                assert md_str is not None, \
                    ("We should have metadata if we have the directory entry %r / %r" %
                     (path_key, name))
                stat_ = json_to_stat(md_str)
                to_iter.append(md_plus_name(name, stat_))

            if not to_iter and not is_empty:
                # NB: THIS SLOWS DOWN MD_CACHE_LOCK
                # TODO: do mvcc by watching FS at the same time we pull directory info
                entries_names = []
                cache_updates = []
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
                        cache_updates.append((str((path / entry.name).normed()),
                                              stat_to_json(entry)))

                if not entries_names:
                    entries_names.append(EMPTY_DIR_ENT)

                # Cache the names we downloaded
                cursor.executemany("INSERT INTO md_cache_entries (path_key, name) VALUES (?, ?)",
                                   ((path_key, name) for name in entries_names))

                # Cache the metadata we've received
                cursor.executemany("REPLACE INTO md_cache (path_key, md) "
                                   "VALUES (?, attr_merge((SELECT md FROM md_cache WHERE path_key = ?), ?))",
                                   ((sub_path_key, sub_path_key, md_str)
                                    for (sub_path_key, md_str) in cache_updates))

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

class SharedLock(object):
    def __init__(self):
        self.cond = threading.Condition()
        self.readers = 0
        self.want_write = 0
        self.writers = 0

    def _rep(self):
        if self.writers > 1 or self.writers < 0:
            return False

        if self.want_write < self.writers:
            return False

        if self.writers and self.readers:
            return False

        return True

    def acquire(self):
        with self.cond:
            assert self._rep()
            self.want_write += 1
            while self.readers or self.writers:
                self.cond.wait()
            self.writers += 1
            assert self._rep()

    def release(self):
        with self.cond:
            assert self._rep()
            self.writers -= 1
            self.want_write -= 1
            self.cond.notify_all()
            assert self._rep()

    def acquire_shared(self):
        with self.cond:
            assert self._rep()
            while self.want_write or self.writers:
                self.cond.wait()
            self.readers += 1
            assert self._rep()

    def release_shared(self):
        with self.cond:
            assert self._rep()
            self.readers -= 1
            self.cond.notify_all()
            assert self._rep()

    @contextlib.contextmanager
    def shared_context(self):
        self.acquire_shared()
        try:
            yield
        finally:
            self.release_shared()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *n):
        self.release()

# File downloads start on first call to pread()
class CachedFile(object):
    def __init__(self, fs, stat):
        self._real_fs = fs
        self.cache_folder = fs._cache_folder
        self.fs = fs._fs
        self.id = stat.id
        self._stat = stat
        self.reset_lock = SharedLock()
        self.is_closed = False

        self.cond = None
        self.thread = None
        self.stop_signal = None
        self.cached_file = None

    def stat(self):
        return self._stat

    def _thread_has_started(self):
        assert (self.stop_signal is None) == (self.thread is None) == (self.cond is None)
        return self.thread is not None

    def _reset(self):
        # start thread to stream file in
        def stream_file():
            # XXX: Handle errors
            with contextlib.closing(self.fs.open_by_id(self.id)) as fsource:
                if self._stat is None:
                    stat = self.fs.fstat(fsource)
                else:
                    stat = self._stat

                is_temp = False
                if self.cache_folder is None:
                    self.cached_file = tempfile.TemporaryFile()
                    is_temp = True
                else:
                    fn = '%s-%d.bin' % (self.id, utctimestamp(stat.ctime))
                    self.cached_file = open(os.path.join(self.cache_folder, fn), 'a+b')
                    # XXX: make sure no other process has `cached_file` open

                    # Restart a previous download
                    # TODO: check integrity of file
                    amt = self.cached_file.tell()

                    with self.cond:
                        assert not self.stored and self.eof is None
                        self.stored = amt
                        self.eof = amt if amt == stat.size else None
                        self.cond.notify_all()
                        if self.eof is not None: return

                    if self._stat is not None:
                        stat2 = self.fs.fstat(fsource)
                        if stat2.ctime != self._stat.ctime:
                            log.warning("Current file version does not match expected!")
                            return

                    fsource.seek(amt, io.SEEK_CUR)
                while True:
                    if self.stop_signal.is_set():
                        log.debug("File download stopped early!")
                        return

                    buf = fsource.read(2 ** 16)
                    if not buf: break
                    self.cached_file.write(buf)
                    self.cached_file.flush()
                    with self.cond:
                        self.stored += len(buf)
                        self.cond.notify_all()

                with self.cond:
                    self.eof = self.stored
                    self.cond.notify_all()

                if not is_temp:
                    # now that we have a new file, prune cache
                    # in case the cache has exceeded its limit
                    self._real_fs._prune_event.set()

                log.debug("Done downloading %r", self.id)

        with self.cond:
            self.stored = 0
            self.eof = None

        self.stop_signal = threading.Event()
        self.thread = threading.Thread(target=stream_file, daemon=True)
        self.thread.start()

    def _wait_for_range(self, offset, size):
        with self.cond:
            while (self.stored < offset + size and self.eof is None):
                self.cond.wait()

    def _should_wait(self, offset, size):
        with self.cond:
            # if this is currently being downloaded, then just wait
            if (offset + size <= self.stored + 2 ** 16 or
                offset == self.stored):
                return True

            return not (self.stored < offset + size and self.eof is None)

    def pread(self, offset, size):
        ctx = self.reset_lock.shared_context()

        while True:
            with ctx:
                if self.is_closed:
                    raise Exception("file is closed")

                if not self._thread_has_started():
                    # if thread hasn't started, then upgrade to exclusive lock
                    # and start it
                    if ctx is not self.reset_lock:
                        ctx = self.reset_lock
                        continue

                    self.cond = threading.Condition()
                    self._reset()

                if not self._should_wait(offset, size):
                    log.debug("Bypassing file cache %r", (offset, size))
                    try:
                        with contextlib.closing(self.fs.open_by_id(self.id)) as fsource:
                            return fsource.pread(offset, size)
                    finally:
                        log.debug("Done bypassing file cache %r", (offset, size))

                self._wait_for_range(offset, size)

                # TODO: port to windows, can use ReadFile
                return os.pread(self.cached_file.fileno(), size, offset)

    def close(self):
        with self.reset_lock:
            if self.is_closed:
                return
            self.is_closed = True
            if self._thread_has_started():
                self.stop_signal.set()
                self.thread.join()
                self.cached_file.close()
                self.cached_file = None

LiveFileMetadata = collections.namedtuple('LiveFileMetadata',
                                          ["cached_file", "open_files"])

class _File(io.RawIOBase):
    def __init__(self, fs, stat):
        self._fs = fs

        with self._fs._file_cache_lock:
            try:
                live_md = self._fs._open_files_by_id[stat.id]
            except KeyError:
                if stat.type == "file":
                    cached_file = CachedFile(fs, stat)
                else:
                    cached_file = self._fs._fs.open_by_id(stat.id)

                live_md = self._fs._open_files_by_id[stat.id] = \
                          LiveFileMetadata(cached_file=cached_file,
                                           open_files=set())

            live_md.open_files.add(self)

        self._live_md = live_md
        self._id = stat.id
        self._stat = stat

        self._lock = threading.Lock()
        self._offset = 0

    def stat(self):
        # NB: handle directory handles
        if not isinstance(self._live_md.cached_file, CachedFile):
            return self._stat
        return self._live_md.cached_file.stat()

    def pread(self, offset, size):
        return self._live_md.cached_file.pread(offset, size)

    def readinto(self, ibuf):
        with self._lock:
            obuf = self.pread(self._offset, len(ibuf))
            ibuf[:len(obuf)] = obuf
            self._offset += len(obuf)
            return len(obuf)

    def readable(self):
        return True

    def close(self):
        toclose = None
        with self._fs._file_cache_lock:
            self._live_md.open_files.remove(self)
            if not self._live_md.open_files:
                toclose = self._live_md.cached_file
                popped = self._fs._open_files_by_id.pop(self._id)
                assert popped is self._live_md
        if toclose is not None:
            toclose.close()

class FileSystem(object):
    def __init__(self, fs, cache_folder=None):
        if sqlite3.sqlite_version_info < (3, 9, 0):
            raise Exception("Need sqlite version >= 3.9.0, you have: %r" % (sqlite3.sqlite_version,))

        use_shared_cache = True

        self._cache_folder = cache_folder
        self._db_file = "file:dropboxvfs-%d?mode=memory" % (id(self),)
        self._fs = fs

        if use_shared_cache:
            self._db_file += "&cache=shared"
            # Application locking is only necessary in shared cache mode
            # otherwise SQLite will do locking for us
            self._db_lock = SharedLock()
        else:
            assert ("mode=memory" in self._db_file or
                    ":memory:" in self._db_file)
            self._db_lock = None

        self._local = threading.local()

        # NB: at least one conn must be held open if this is an
        #     in-memory DB
        self._conn = self._init_db()

        self._file_cache_lock = threading.Lock()
        self._open_files_by_id = {}

        # watch file system and clear cache on any changes
        # NB: we need to use a 'db style' watch because we need the
        #     ids, and create_watch() doesn't promise ids
        try:
            create_db_watch = self._fs.create_db_style_watch
        except AttributeError:
            self._watch_stop = None
        else:
            self._watch_stop = create_db_watch(self._handle_changes)

        # start thread that prunes cache
        self._prune_event = threading.Event()
        self._close_prune_thread = False
        threading.Thread(target=self._prune_thread, daemon=True).start()

    def close(self):
        self._close_prune_thread = True
        self._prune_event.set()
        self._conn.close()
        if self._watch_stop is not None:
            self._watch_stop()

    def _prune_thread(self):
        if not self._cache_folder:
            return

        # prune every 30 minutes
        PRUNE_PERIOD = 30 * 60

        while not self._close_prune_thread:
            # compute total free space on disk
            vfs_stat = os.statvfs(self._cache_folder)
            free_space = vfs_stat.f_bsize * vfs_stat.f_bavail;

            # compute total space taken by cache
            cache_entries = []
            for name in os.listdir(self._cache_folder):
                cache_entries.append((name, os.lstat(os.path.join(self._cache_folder, name))))

            cache_size = sum(st.st_size for (_, st) in cache_entries)

            # sort by ascending atime, descending size
            cache_entries.sort(key=lambda name_st_pair: (name_st_pair[1].st_atime,
                                                         -name_st_pair[1].st_size))

            # P: `cache / (cache + free_space)`
            # N: configurable value from [0, 1]

            N = 0.10

            # delete oldest accessed files, largest files until P<=N
            potential_free_space = cache_size + free_space
            for (name, st) in cache_entries:
                if cache_size / potential_free_space <= N:
                    break

                os.unlink(os.path.join(self._cache_folder, name))

                cache_size -= st.st_size

            self._prune_event.wait(PRUNE_PERIOD)
            self._prune_event.clear()

    def _init_db(self):
        conn = self._create_db_conn()

        conn.executescript("""
        CREATE TABLE IF NOT EXISTS md_cache
        ( path_key TEXT PRIMARY KEY
        , md TEXT
        );

        CREATE TABLE IF NOT EXISTS md_cache_entries
        ( path_key TEXT NOT NULL
        , name TEXT NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS md_cache_entries_unique
        on md_cache_entries (path_key, file_name_norm(name));
        """)
        conn.commit()

        return conn

    def _norm_join_sql(self, path_key, name):
        return str((self._fs.parse_path(path_key) / name).normed())

    def _create_db_conn(self):
        conn = sqlite3.connect(self._db_file, factory=WeakrefableConnection, uri=True)
        conn.create_function("attr_merge", 2, wrap_show_exc(attr_merge_sql))
        conn.create_function("norm_join", 2, wrap_show_exc(self._norm_join_sql))
        register_deterministic_function(conn, "file_name_norm", 1, wrap_show_exc(file_name_norm_2))
        return conn

    def _get_db_conn(self):
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = self._local.conn = self._create_db_conn()
        return conn

    def _handle_changes(self, changes):
        conn = self._get_db_conn()
        with trans(conn, self._db_lock, is_exclusive=True):
            cursor = conn.cursor()

            if changes == "reset":
                cursor.execute("DELETE FROM md_cache");
                cursor.execute("DELETE FROM md_cache_entries");
                return

            for change in changes:
                # NB: the metadata we currently have could be newer than this change
                #     the file will temporarily revert while we catch up to the newer state
                # TODO: don't process stale data, need 'server_modified' on all metadata
                #       entries from the dropbox api

                path_key = change.path_lower
                normed_path = self.create_path(*([] if change.path_lower == "/" else change.path_lower[1:].split("/")))
                name = change.name
                parent_path_key = str(normed_path.parent)
                if isinstance(change, dropbox.files.DeletedMetadata):
                    # remove from the directory tree cache
                    cursor.execute("DELETE FROM md_cache_entries WHERE path_key = ? and file_name_norm(name) = ?",
                                   (parent_path_key, file_name_norm(name)))
                    if cursor.rowcount:
                        # insert directory empty marker if there are no more
                        # files under this directory
                        conn.execute("""
                        INSERT INTO md_cache_entries (path_key, name)
                        SELECT ?, ? WHERE
                        (SELECT EXISTS(SELECT * FROM md_cache_entries WHERE
                                       path_key = ?)) = 0
                        """,
                        (parent_path_key, name, parent_path_key))

                    # set deleted in the metadata cache
                    cursor.execute("UPDATE md_cache SET md = ? WHERE path_key = ?",
                                   (json.dumps(None), path_key,))
                else:
                    # add to directory tree cache if parent is in cache
                    cursor.execute("""
                    INSERT OR REPLACE INTO md_cache_entries (path_key, name)
                    SELECT ?, ? WHERE
                    (SELECT EXISTS(SELECT * FROM md_cache_entries WHERE path_key = ?))
                    """, (parent_path_key, name, parent_path_key))

                    if cursor.rowcount:
                        # delete directory empty marker if it existed
                        cursor.execute("DELETE FROM md_cache_entries WHERE path_key = ? and name = ?", (parent_path_key, EMPTY_DIR_ENT))

                        # since we have the directory in cache, we should cache this entry
                        cursor.execute("INSERT OR REPLACE INTO md_cache (path_key, md) "
                                       "VALUES (?, ?)",
                                       (path_key, stat_to_json(dbmd_to_stat(change))))
                    else:
                        # update the metadata we have on this file
                        cursor.execute("UPDATE md_cache SET md = ? WHERE path_key = ?",
                                       (stat_to_json(dbmd_to_stat(change)), path_key))

    def create_path(self, *args):
        return self._fs.create_path(*args)

    def open(self, path):
        return _File(self, self.stat(path))

    def open_directory(self, path):
        return _Directory(self, path)

    def stat_has_attr(self, attr):
        return self._fs.stat_has_attr(attr)

    def stat(self, path):
        conn = self._get_db_conn()
        # We use BEGIN IMMEDIATE here because SQLite's deferred transactions
        # will immediately throw a BUSY error if two threads concurrently attempt to
        # upgrade from READ->WRITE.
        # TODO: Start transaction with DEFERRED and restart with IMMEDIATE
        #       if a write is necessary
        with trans(conn, self._db_lock, is_exclusive=True), contextlib.closing(conn.cursor()) as cursor:
            path_key = str(path.normed())

            cursor.execute("SELECT md FROM md_cache WHERE path_key = ? limit 1",
                           (path_key,))
            row = cursor.fetchone()
            if row is None:
                # if it didn't exist in the md_cache, check if the
                # parent exists in md_cache_entries, if so then this
                # file doesn't exist
                (parent_has_been_iterated,) = cursor.execute("""
                SELECT EXISTS(SELECT * FROM md_cache_entries WHERE path_key = ?)
                """, (str(path.parent.normed()),)).fetchone()

                if parent_has_been_iterated:
                    stat = None
                else:
                    # NB: Potentially slow!
                    # TODO: do mvcc before storing back in md_cache
                    try:
                        stat = self._fs.stat(path)
                    except FileNotFoundError:
                        stat = None

                    md_str = None if stat is None else stat_to_json(stat)

                    cursor.execute("INSERT INTO md_cache (path_key, md) values (?, ?)",
                                   (path_key, md_str))
            else:
                (md,) = row
                stat =  None if md is None else json_to_stat(md)

        if stat is None:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        else:
            # if the file is currently open, return the currently open stat instead
            with self._file_cache_lock:
                try:
                    md = self._open_files_by_id[stat.id]
                except KeyError:
                    pass
                else:
                    # NB: could be a directory otherwise
                    if isinstance(md.cached_file, CachedFile):
                        return md.cached_file.stat()

        return stat

    def fstat(self, fobj):
        return fobj.stat()

    def create_watch(self, cb, handle, *n, **kw):
        return self._fs.create_watch(cb, handle._live_md.cached_file, *n, **kw)

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

    tmp_dir = tempfile.mkdtemp()
    try:
        fs = FileSystem(backing_fs, cache_folder=tmp_dir)

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
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
