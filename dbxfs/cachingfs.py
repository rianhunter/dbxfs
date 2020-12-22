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
import queue
import tempfile
import threading
import traceback
import shutil
import sqlite3
import sys
import time
import weakref

from userspacefs.util_dumpster import utctimestamp, PositionIO, null_context, quick_container, IterableDirectory

from dbxfs.dbxfs import md_to_stat as dbmd_to_stat

import dropbox

log = logging.getLogger(__name__)

if not hasattr(os, 'O_ACCMODE'):
    O_ACCMODE = 0x3
    for accmode in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
        assert (O_ACCMODE & accmode) == accmode

class attr_merge(object):
    def __init__(self, *n):
        attrs = set()
        for obj in n:
            for name in obj.attrs:
                setattr(self, name, getattr(obj, name))
                attrs.add(name)
        self.attrs = list(attrs)

    def _replace(self, **kw):
        class Foo(object): pass
        tomerge = Foo()
        for (k, v) in kw.items():
            setattr(tomerge, k, v)
        tomerge.attrs = list(kw)
        return attr_merge(self, tomerge)

    def __repr__(self):
        return 'attr_merge(' + ', '.join('%s=%r' % (k, getattr(self, k)) for k in self.attrs) + ')'

Name = collections.namedtuple('Name', ['name', 'attrs'])
def md_plus_name(name, md):
    return attr_merge(Name(name, attrs=['name']), md)

REQUIRED_ATTRS = ["mtime", "type", "size", "id", "ctime", "rev"]
Stat = collections.namedtuple("Stat", REQUIRED_ATTRS + ["attrs"])

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
    info['attrs'] = REQUIRED_ATTRS
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

try:
    # NB: the sqlite3 library should already be loaded
    #     but we specify noload just in case
    if sys.platform == "darwin":
        RTLD_NOLOAD = 0x10
    elif sys.platform.startswith("linux"):
        RTLD_NOLOAD = 0x04
    else:
        RTLD_NOLOAD = 0

    pysqlite_dll = ctypes.PyDLL(_sqlite3.__file__, ctypes.RTLD_GLOBAL | RTLD_NOLOAD)

    sqlite3_close_proto = ctypes.CFUNCTYPE(
        ctypes.c_int, # return code
        ctypes.c_void_p, # db argument
    )

    try:
        sqlite3_close = sqlite3_close_proto(("sqlite3_close_v2",
                                             pysqlite_dll))
    except Exception:
        sqlite3_close = sqlite3_close_proto(("sqlite3_close",
                                             pysqlite_dll))
except Exception:
    pysqlite_dll = None
    sqlite3_close = None

class pysqlite_Connection_header(ctypes.Structure):
    _fields_ = [("a", ctypes.c_ssize_t),
                ("b", ctypes.c_void_p)]

def get_dbpp(conn):
    return ctypes.cast(id(conn) +
                       ctypes.sizeof(pysqlite_Connection_header),
                       ctypes.POINTER(ctypes.c_void_p))

_hold_ref_lock = threading.Lock()
_hold_ref = weakref.WeakKeyDictionary()
def register_deterministic_function(conn, name, num_params, func):
    if not isinstance(conn, sqlite3.Connection):
        raise Exception("Bad connection object: %r" % (conn,))

    if sys.version_info >= (3, 8):
        return conn.create_function(name, num_params, func, deterministic=True)

    if pysqlite_dll is None:
        raise Exception("can't create function")

    # This is a hack, oh well this is how I roll

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
    dbp = get_dbpp(conn).contents

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

MUST_MUTATE = object()

EMPTY_DIR_ENT = "/empty/"

class WeakrefableConnection(sqlite3.Connection):
    def __init__(self, *n, **kw):
        # we call close() in __del__ which might happen on a different thread
        kw['check_same_thread'] = False
        sqlite3.Connection.__init__(self, *n, **kw)
        self.funcs = []

    def create_function(self, name, num_params, func, **kw):
        toret = sqlite3.Connection.create_function(self, name, num_params, func, **kw)
        # NB: since we call sqlite3_close outside of GIL, we don't want
        #     it to trigger deallocation of the function objects. instead
        #     make that happen when the connection object is deallocated
        #     by adding an extra reference to the connection object itself
        self.funcs.append(func)
        return toret

    def close(self):
        # Current versions of pysqlite call sqlite3_close() on dealloc or close()
        # without releasing the GIL. This causes a deadlock if it tries to grab lock
        # that is internal to sqlite3 that another thread already has.
        # The correct fix is to release the gil before calling sqlite3_close()
        # but since we cannot change the _sqlite module our workaround is to use a
        # special ctypes version of close.
        if sqlite3_close is None:
            return sqlite3.Connection.close(self)

        # get dp pointer from connection object
        dbpp = get_dbpp(self)

        # get db pointer
        db_ptr = dbpp.contents

        # we need to call call base method
        # to finalize all statements before closing database
        # but we have to set database pointer to null so it doesn't
        # call sqlite3_close() on our database without first
        dbpp[0] = ctypes.c_void_p()
        try:
            sqlite3.Connection.close(self)
        except Exception:
            dbpp[0] = db_ptr
            raise

        if db_ptr:
            rc = sqlite3_close(dbptr)
            if rc:
                raise Exception("Error while creating function: %r" % (rc,))

    def __del__(self):
        self.close()

class _Directory(IterableDirectory):
    def _get_to_iter(self, mutate, fs, path):
        refreshed = True

        conn = fs._get_db_conn()

        path_key = str(path.normed())

        with trans(conn, fs._db_lock, is_exclusive=mutate), contextlib.closing(conn.cursor()) as cursor:
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

            if mutate:
                stat_num = fs._get_stat_num(cursor, path_key)

        # if entries was empty, then fill it
        if not to_iter and not is_empty:
            if not mutate:
                return MUST_MUTATE

            entries_names = []
            cache_updates = []
            with contextlib.closing(fs._fs.open_directory(path)) as dir_:
                for entry in dir_:
                    entries_names.append(entry.name)
                    to_iter.append(entry)
                    cache_updates.append((str((path / entry.name).normed()),
                                          entry))

            if not entries_names:
                entries_names.append(EMPTY_DIR_ENT)

            with trans(conn, fs._db_lock, is_exclusive=True), contextlib.closing(conn.cursor()) as cursor:
                new_stat_num = fs._get_stat_num(cursor, path_key)
                if stat_num == new_stat_num:
                    # Cache the names we downloaded
                    cursor.executemany("INSERT INTO md_cache_entries "
                                       "(path_key, name) VALUES (?, ?)",
                                       ((path_key, name) for name in entries_names))

                    cursor.execute("update md_cache_counter "
                                   "set counter = counter + 1 "
                                   "where path_key = ?",
                                   (path_key,))

                    # Cache the metadata we've received
                    # NB: we know none of the child entries has been changed since we
                    #     check dir num (updates to children always increment parent dir num)
                    #     so we can safely update them.
                    for (sub_path_key, stat) in cache_updates:
                        fs._update_md(cursor, sub_path_key, stat)
                else:
                    refreshed = False

        return (to_iter, refreshed)

    def __init__(self, fs, path):
        mutate = False
        while True:
            res = self._get_to_iter(mutate, fs, path)
            if res is MUST_MUTATE:
                mutate = True
                continue
            (to_iter, self._refreshed) = res
            self._it = iter(to_iter)
            return

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

DOWNLOAD_UNIT = 2 ** 16

# File downloads start on first call to pread()
class StreamingFile(object):
    def __init__(self, fs, stat):
        assert stat.rev is not None, (
            "Empty stat rev for file: %r" % (stat,)
        )

        self._real_fs = fs
        self.cache_folder = fs._cache_folder
        self.fs = fs._fs
        self._stat = stat
        self.reset_lock = SharedLock()
        self.is_closed = False

        self.cond = None
        self.thread = None
        self.stop_signal = None
        self.cached_file = None
        self.eio = False

    def stat(self):
        return self._stat

    def _thread_has_started(self):
        assert (self.stop_signal is None) == (self.cond is None)
        return self.cond is not None

    def _start_thread(self):
        self.cond = threading.Condition()
        self.stop_signal = threading.Event()
        self._reset()

    def _reset(self):
        # start thread to stream file in
        def stream_file(is_temp, amt):
            while not self.stop_signal.is_set():
                try:
                    if not is_temp:
                        self._real_fs._check_space(self._stat.size - amt)

                    # Use offset to skip bytes if we already have them
                    with contextlib.closing(self.fs.x_read_stream(self._stat.rev, offset=amt)) as fsource:
                        while True:
                            if self.stop_signal.is_set():
                                log.debug("File download stopped early!")
                                return

                            buf = fsource.read(DOWNLOAD_UNIT)
                            if not buf: break

                            self.cached_file.write(buf)
                            self.cached_file.flush()
                            with self.cond:
                                self.stored += len(buf)
                                self.cond.notify_all()

                            amt += len(buf)

                        with self.cond:
                            self.eof = self.stored
                            self.cond.notify_all()

                        if not is_temp:
                            # now that we have a new file, prune cache
                            # in case the cache has exceeded its limit
                            self._real_fs._prune_event.set()

                        log.debug("Done downloading %r", self._stat.rev)
                    break
                except Exception as e:
                    with self.cond:
                        self.eio = True
                        self.cond.notify_all()
                    # If we hit an out-of-space condition, then
                    # stop downloading, redirect future requests to network (via self.eio)
                    if isinstance(e, OSError) and e.errno == errno.ENOSPC:
                        break
                    log.exception("Error downloading file, sleeping...")
                    self.stop_signal.wait(100)
                    with self.cond:
                        self.eio = False

        if self.cache_folder is not None:
            try:
                os.makedirs(self.cache_folder)
            except OSError:
                pass

        if self.cache_folder is not None:
            try:
                with tempfile.NamedTemporaryFile(dir=self.cache_folder,
                                                 delete=False) as f:
                    temp_path = f.name

                fn = '%s.bin' % (self._stat.rev)
                # NB: make sure no other process uses the cached file if it exists
                try:
                    os.rename(os.path.join(self.cache_folder, fn), temp_path)
                except FileNotFoundError:
                    pass
                self.cached_file = open(temp_path, 'a+b')
            except (IOError, OSError):
                pass

        if self.cached_file is None:
            self.cached_file = tempfile.TemporaryFile()
            is_temp = True
        else:
            is_temp = False

        # Restart a previous download
        # TODO: check integrity of file
        amt = self.cached_file.tell()

        with self.cond:
            self.stored = amt
            self.eof = amt if amt == self._stat.size else None

        if self.eof is not None:
            return

        self.thread = threading.Thread(target=stream_file,
                                       args=(is_temp, amt),
                                       daemon=True)
        self.thread.start()

    def _wait_for_range(self, offset, size):
        with self.cond:
            while True:
                assert self.cached_file is not None

                if self.stored >= offset + size or self.eof is not None:
                    return False

                if self.eio:
                    return True

                self.cond.wait()

    def _should_wait(self, offset, size):
        with self.cond:
            assert self.cached_file is not None

            # we already have the data, so we can "wait"
            if self.stored >= offset + size or self.eof is not None:
                return True

            if self.eio:
                return False

            # if this is currently being downloaded, then just wait
            if (offset + size <= self.stored + DOWNLOAD_UNIT or
                offset == self.stored):
                return True

            return False

    def pread(self, size, offset):
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

                    self._start_thread()

                    # in case we loop again below
                    ctx = self.reset_lock.shared_context()

                if not size:
                    return b''

                if not self._should_wait(offset, size):
                    log.debug("Bypassing file cache %r", (offset, size))
                    try:
                        with contextlib.closing(self.fs.x_open_by_rev(self._stat.rev)) as fsource:
                            return self.fs.pread(fsource, size, offset)
                    except AssertionError:
                        raise
                    except Exception as e:
                        raise OSError(errno.EIO, os.strerror(errno.EIO)) from e
                    finally:
                        log.debug("Done bypassing file cache %r", (offset, size))

                redo = self._wait_for_range(offset, size)
                if redo:
                    continue

                # TODO: port to windows, can use ReadFile
                return os.pread(self.cached_file.fileno(), size, offset)

    def close(self):
        th = None
        with self.reset_lock:
            if self.is_closed:
                return
            self.is_closed = True
            if self._thread_has_started():
                self.stop_signal.set()
                if self.thread is not None:
                    self.thread.join()
                self.cached_file.close()
                if isinstance(getattr(self.cached_file, 'name', None), str):
                    try:
                        fn = os.path.join(self.cache_folder,
                                          '%s.bin' % (self._stat.rev))
                        os.rename(self.cached_file.name, fn)
                    except Exception:
                        log.exception("Unexpected failure to unlink lock file")
                self.cached_file = None

class NullFile(object):
    def __init__(self, id_):
        now_ = datetime.datetime.utcfromtimestamp(0)
        self._stat = Stat(size=0, mtime=now_, ctime=now_, type='file', id=id_,
                          rev=None, attrs=REQUIRED_ATTRS)

    def stat(self):
        return self._stat

    def pread(self, size, offset):
        return b''

    def close(self):
        pass

SQLITE_FILE_BLOCK_SIZE = 4096
class SQLiteFrontFile(PositionIO):
    # NB: SqliteFrontFile relies on backfile argument not mutating
    # NB: backfile becomes owned by SQLiteFrontFile after construction
    def __init__(self, backfile):
        PositionIO.__init__(self)

        self._backfile = backfile
        self._local = threading.local()
        (fd, self._file_path) = tempfile.mkstemp()
        os.close(fd)

        self._db_file = "file://%s" % (self._file_path,)

        use_shared_cache = True
        if use_shared_cache:
            self._db_file += "?cache=shared"
            # Application locking is only necessary in shared cache mode
            # otherwise SQLite will do locking for us
            self._db_lock = SharedLock()
        else:
            self._db_lock = None

        stat = self._backfile.stat()

        conn = self._init_db()

        with trans(conn, self._db_lock, is_exclusive=True), \
             contextlib.closing(conn.cursor()) as cursor:
            self._update_write_md(cursor, stat.size, stat.ctime, stat.mtime)

    def _update_write_md(self, cursor, size, ctime, mtime):
        toupdate = []
        if size is not None:
            toupdate.append(("size", json.dumps(size)))
        if ctime is not None:
            toupdate.append(("ctime", json.dumps(utctimestamp(ctime))))
        if mtime is not None:
            toupdate.append(("mtime", json.dumps(utctimestamp(mtime))))
        cursor.executemany("INSERT OR REPLACE INTO md (name, value) VALUES (?, ?)",
                           toupdate)

    def replace_underlying(self, new_backfile):
        stat = self.stat()
        new_stat = new_backfile.stat()

        # basic sanity check
        assert stat.size == new_stat.size

        conn = self._get_db_conn()

        with trans(conn, self._db_lock, is_exclusive=True), \
             contextlib.closing(conn.cursor()) as cursor:
            self._update_write_md(cursor, new_stat.size, new_stat.ctime, new_stat.mtime)

            oldbackfile = self._backfile
            self._backfile = new_backfile
            oldbackfile.close()

    def stat(self):
        conn = self._get_db_conn()

        stat_dict = {}
        with trans(conn, self._db_lock), contextlib.closing(conn.cursor()) as cursor:
            cursor.execute("SELECT name, value FROM md WHERE name IN ('size', 'mtime', 'ctime')")
            for (name, value) in cursor:
                if name in ["mtime", "ctime"]:
                    value = datetime.datetime.utcfromtimestamp(value)
                elif name == "size":
                    value = int(value)
                stat_dict[name] = value

        r = self._backfile.stat()
        return Stat(type=r.type, id=r.id, rev=None, attrs=REQUIRED_ATTRS,
                    **stat_dict)

    def close(self):
        if self.closed:
            return
        try:
            os.unlink(self._file_path)
        except Exception:
            log.warning("Error unlinking dirty cache file",
                        exc_info=True)
        self._backfile.close()
        super().close()

    def _init_db(self):
        conn = self._get_db_conn()

        conn.executescript("""
        CREATE TABLE IF NOT EXISTS blocks
        ( blkidx INTEGER PRIMARY KEY
        , data BUFFER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS md
        ( name STRING PRIMARY KEY
        , value STRING NOT NULL
        )
        """)
        conn.commit()

        return conn

    def _create_db_conn(self):
        return sqlite3.connect(self._db_file, factory=WeakrefableConnection, uri=True)

    def _get_db_conn(self):
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = self._local.conn = self._create_db_conn()
        return conn

    def is_dirty(self):
        conn = self._get_db_conn()
        with trans(conn, self._db_lock), contextlib.closing(conn.cursor()) as cursor:
            cursor.execute("SELECT EXISTS(SELECT * FROM blocks)")
            if cursor.fetchone()[0]:
                return True
            cursor.execute("SELECT value FROM md WHERE name = 'size'")
            if cursor.fetchone()[0] != self._backfile.stat().size:
                return True
            return False

    def readable(self):
        return True

    def _pread(self, cursor, size, offset):
        blkidx_start = offset // SQLITE_FILE_BLOCK_SIZE
        blkidx_start_offset = offset % SQLITE_FILE_BLOCK_SIZE

        blkidx_end = (offset + size) // SQLITE_FILE_BLOCK_SIZE
        blkidx_end_offset = (offset + size) % SQLITE_FILE_BLOCK_SIZE

        if not blkidx_end_offset:
            blkidx_end -= 1
            blkidx_end_offset = SQLITE_FILE_BLOCK_SIZE

        blks = [None] * (blkidx_end - blkidx_start + 1)

        # get data from writeable sqlite overly
        cursor.execute("SELECT blkidx, data FROM blocks WHERE blkidx >= ? AND blkidx <= ?",
                       (blkidx_start, blkidx_end))
        for (blkidx, data) in cursor:
            blks[blkidx - blkidx_start] = data

        cursor.execute("SELECT value FROM md WHERE name = 'size'")
        (extent_of_file,) = cursor.fetchone()
        extent_of_file = int(extent_of_file)

        # get remaining blocks from backing store
        # NB: read everything at once to minimize potential latency
        data = self._backfile.pread(len(blks) * SQLITE_FILE_BLOCK_SIZE,
                                    blkidx_start * SQLITE_FILE_BLOCK_SIZE)
        for (idx, _) in enumerate(blks):
            if blks[idx] is not None:
                continue
            read_ = data[idx * SQLITE_FILE_BLOCK_SIZE : (idx + 1) * SQLITE_FILE_BLOCK_SIZE]
            blks[idx] = b'%s%s' % (read_, b'\0' * (SQLITE_FILE_BLOCK_SIZE - len(read_)))

        assert all(len(a) == SQLITE_FILE_BLOCK_SIZE for a in blks)

        # fix up beginning and ending blocks
        if blks:
            if blkidx_start == blkidx_end:
                assert len(blks) == 1
                blks[0] = blks[0][blkidx_start_offset:blkidx_end_offset]
            else:
                blks[0] = blks[0][blkidx_start_offset:]
                blks[-1] = blks[-1][:blkidx_end_offset]

        # concatenate data and return
        toret = b''.join(blks)

        # cutoff trailing bytes
        if offset + size > extent_of_file:
            toret = toret[:-(offset + size - extent_of_file)]

        return toret

    def pread(self, size, offset):
        conn = self._get_db_conn()
        with trans(conn, self._db_lock), \
             contextlib.closing(conn.cursor()) as cursor:
            return self._pread(cursor, size, offset)

    def writable(self):
        return True

    def _pwrite(self, cursor, data, offset):
        size = len(data)

        blkidx_start = offset // SQLITE_FILE_BLOCK_SIZE
        blkidx_start_offset = offset % SQLITE_FILE_BLOCK_SIZE

        blkidx_end = (offset + size) // SQLITE_FILE_BLOCK_SIZE
        blkidx_end_offset = (offset + size) % SQLITE_FILE_BLOCK_SIZE
        if not blkidx_end_offset:
            blkidx_end -= 1
            blkidx_end_offset = SQLITE_FILE_BLOCK_SIZE

        # write data to backfile
        desired_header_size = blkidx_start_offset
        header = self._pread(cursor, desired_header_size, blkidx_start * SQLITE_FILE_BLOCK_SIZE)
        desired_footer_size = (blkidx_end + 1) * SQLITE_FILE_BLOCK_SIZE - (offset + size)
        footer = self._pread(cursor, desired_footer_size, offset + size)

        block_aligned_data = (b'%s%s%s%s%s' %
                              (header, b'\0' * (desired_header_size - len(header)),
                               data,
                               footer, b'\0' * (desired_footer_size - len(footer))))
        assert not (len(block_aligned_data) % SQLITE_FILE_BLOCK_SIZE)

        hai = list((idx, block_aligned_data[(idx - blkidx_start) * SQLITE_FILE_BLOCK_SIZE:
                                            (idx - blkidx_start + 1) * SQLITE_FILE_BLOCK_SIZE])
                   for idx in range(blkidx_start, blkidx_end + 1))
        cursor.executemany("INSERT OR REPLACE INTO blocks (blkidx, data) VALUES (?, ?)",
                           hai)

        cursor.execute("SELECT value FROM md WHERE name = 'size'")
        (extent_of_file,) = cursor.fetchone()
        extent_of_file = int(extent_of_file)

        new_extent_of_file = max(offset + size, extent_of_file)
        self._update_write_md(cursor, new_extent_of_file,
                              datetime.datetime.utcnow(), datetime.datetime.utcnow())

        return len(data)

    def pwrite(self, data, offset):
        conn = self._get_db_conn()
        with trans(conn, self._db_lock, is_exclusive=True), \
             contextlib.closing(conn.cursor()) as cursor:
            return self._pwrite(cursor, data, offset)

    def ptruncate(self, offset):
        blkidx_start = offset // SQLITE_FILE_BLOCK_SIZE
        blkidx_start_offset = offset % SQLITE_FILE_BLOCK_SIZE
        if not blkidx_start_offset:
            blkidx_start -= 1

        conn = self._get_db_conn()
        with trans(conn, self._db_lock, is_exclusive=True), \
             contextlib.closing(conn.cursor()) as cursor:
            cursor.execute("SELECT value FROM md WHERE name = 'size'")
            cur_size = int(cursor.fetchone()[0])
            if offset < cur_size:
                # NB: technically the delete isn't necessary
                #     also this is likely a vain attempt to save space.
                #     doing things in vain is our way of life, so carry on.
                cursor.execute("DELETE FROM blocks WHERE blkidx > ?",
                               (blkidx_start,))
                self._update_write_md(cursor, offset, None, None)
            else:
                # NB: extend with zeros to block data in backfile
                self._pwrite(cursor, b'\0' * (offset - cur_size), cur_size)

class CachedDirectory(object):
    def __init__(self, fs, stat):
        self._fs = fs
        self._stat = stat
        assert self._stat.type == 'directory', (
            "Bad stat for CachedDirectory: %r" % (stat,)
        )
        self._file = self._fs._fs.x_open_by_id(stat.id)

        self._sync_tag = 0

    def stat(self):
        return self._stat

    def queue_sync(self):
        return None

    def sync(self):
        pass

    def pwrite(self, *n, **kw):
        raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))

    def pread(self, *n, **kw):
        raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))

    def ptruncate(self, *n, **kw):
        raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))

    def is_dirty(self):
        return False

    def close(self):
        pass

    def sync(self):
        pass

class CachedFile(object):
    def __init__(self, fs, stat):
        self._fs = fs
        self._id = stat.id
        self._base_stat = stat

        assert stat.type == "file", (
            "Bad stat for CachedFile: %r" % (stat,)
        )
        self._file = SQLiteFrontFile(StreamingFile(fs, stat))

        self._upload_cond = threading.Condition()
        self._upload_now = None
        self._upload_next = None
        self._eio = False
        self._sync_tag = 0
        self._complete_tag = 0
        self._closed = False

        self._thread = threading.Thread(target=self._upload_thread)
        self._thread.start()

    def _upload_thread(self):
        while True:
            try:
                with self._upload_cond:
                    while self._upload_now is None and self._upload_next is None:
                        if self._closed:
                            # File has been closed, abandon ship!
                            self._file.close()
                            return
                        self._upload_cond.wait()
                    assert self._upload_next is None or self._upload_next is self._file
                    if self._upload_next is not None:
                        self._upload_now = self._upload_next
                        self._upload_next = None
                        self._upload_cond.notify_all()
                        sync_tag = self._sync_tag
                        self._file = SQLiteFrontFile(self._file)

                md = None
                self._upload_now.seek(0)
                towrite = self._fs._fs.x_write_stream()
                try:
                    shutil.copyfileobj(self._upload_now, towrite)
                    base_stat = self._base_stat
                    while True:
                        try:
                            md = towrite.finish(self._id,
                                                mtime=self._upload_now.stat().mtime,
                                                mode=("update", base_stat.rev),
                                                strict_conflict=True)
                        except FileExistsError: # This just means conflict
                            try:
                                e_stat = self._fs._fs.x_stat_by_id(self._id)
                            except FileNotFoundError:
                                # file was deleted, black hole this change
                                pass
                            else:
                                # Another client edited this ID,
                                # We overwrite the file as this is
                                # what POSIX allows. Concurrency control
                                # is left to a higher level.
                                base_stat = e_stat
                                continue
                        break
                finally:
                    towrite.close()

                if md is not None:
                    assert md.id == self._id, \
                        "Bad assumption on how overwrite works :("

                    new_stat = dbmd_to_stat(md)

                    if self._fs._cache_folder is not None:
                        try:
                            os.makedirs(self._fs._cache_folder)
                        except OSError:
                            pass

                        to_save = None
                        try:
                            to_save = tempfile.NamedTemporaryFile(dir=self._fs._cache_folder)
                            self._upload_now.seek(0)
                            shutil.copyfileobj(self._upload_now, to_save)
                            # TODO: replace self._upload_now parent's backing file with
                            #       StreamingFile() of local cached version
                            fn = '%s.bin' % (new_stat.rev,)
                            p = os.path.join(self._fs._cache_folder, fn)
                            # Unlink existing file since new one is definitely complete
                            try:
                                os.unlink(p)
                            except FileNotFoundError:
                                pass
                            except Exception:
                                log.warning("Error unlinking existing cache file",
                                            exc_info=True)
                            os.link(to_save.name, p)
                        except Exception:
                            log.warning("Error while linking cached file",
                                        exc_info=True)
                        finally:
                            if to_save is not None:
                                to_save.close()

                    self._base_stat = new_stat

                with self._upload_cond:
                    self._complete_tag = sync_tag
                    self._upload_now = None
                    self._upload_cond.notify_all()
                    self._file.replace_underlying(StreamingFile(self._fs, new_stat))

                self._fs._submit_write(self._id, md)
            except Exception:
                log.exception("Error uploading file, sleeping...")
                with self._upload_cond:
                    self._eio = True
                    self._upload_cond.notify_all()
                    self._upload_cond.wait(100)

    def pread(self, size, offset):
        return self._file.pread(size, offset)

    def pwrite(self, data, offset):
        # NB: grab lock so we don't modify self._file while
        #     it's the argument of SQLiteFrontFile (from _upload_thread)
        with self._upload_cond:
            return self._file.pwrite(data, offset)

    def ptruncate(self, offset):
        with self._upload_cond:
            return self._file.ptruncate(offset)

    def stat(self):
        st = self._file.stat()
        # WriteStream.finish() has second granularity,
        # so keep mtime consistent when it comes back
        return st._replace(mtime=st.mtime.replace(microsecond=0))

    def _queue_sync(self, final=False):
        assert self._upload_next is None or self._upload_next is self._file
        if self._file.is_dirty() and self._upload_next is None:
            self._upload_next = self._file
            self._sync_tag += 1

        if final:
            self._closed = True

        eio = self._eio
        self._eio = False

        if eio or self._closed or self._file.is_dirty():
            self._upload_cond.notify_all()

        return (self._upload_now
                if self._upload_next is None else
                self._upload_next)

    def queue_sync(self):
        with self._upload_cond:
            return self._queue_sync()

    def sync(self):
        with self._upload_cond:
            self._queue_sync()
            sync_tag = self._sync_tag

            # wait for upload
            while not self._eio and self._complete_tag < sync_tag:
                self._upload_cond.wait()

            if self._eio:
                raise OSError(errno.EIO, os.strerror(errno.EIO))

    def is_dirty(self):
        with self._upload_cond:
            return (self._file.is_dirty() or
                    self._upload_next is not None or
                    self._upload_now is not None)

    def close(self):
        with self._upload_cond:
            if self._closed:
                return
            self._queue_sync(final=True)
        if threading.current_thread() is not self._thread:
            self._thread.join()

LiveFileMetadata = collections.namedtuple('LiveFileMetadata',
                                          ["cached_file", "open_files"])

class InvalidFileCacheGenError(Exception): pass

class _File(PositionIO):
    def __init__(self, fs, stat, mode):
        PositionIO.__init__(self)

        self._fs = fs

        with self._fs._file_cache_lock:
            try:
                live_md = self._fs._open_files_by_id[stat.id]
            except KeyError:
                if stat.type == "file":
                    cached_file = CachedFile(fs, stat)
                else:
                    cached_file = CachedDirectory(fs, stat)

                live_md = self._fs._open_files_by_id[stat.id] = \
                          LiveFileMetadata(cached_file=cached_file,
                                           open_files=set())

            live_md.open_files.add(self)

        # NB: this lock lives above all file system locks
        self._lock = SharedLock()
        self._live_md = live_md
        self._id = stat.id
        self._stat = stat

        self._mode = mode

        if self._mode & os.O_TRUNC:
            self._live_md.cached_file.ptruncate(0)

    def stat(self):
        with self._lock.shared_context():
            if self._live_md is None:
                raise OSError(errno.EBADF, os.strerror(errno.EBADF))
            return self._live_md.cached_file.stat()

    def sync(self):
        with self._lock.shared_context():
            if self._live_md is None:
                raise OSError(errno.EBADF, os.strerror(errno.EBADF))

            return self._live_md.cached_file.sync()

    def pread(self, size, offset):
        if not self.readable():
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))

        with self._lock.shared_context():
            if self._live_md is None:
                raise OSError(errno.EBADF, os.strerror(errno.EBADF))

            return self._live_md.cached_file.pread(size, offset)

    def readable(self):
        return (self._mode & os.O_ACCMODE) in (os.O_RDONLY, os.O_RDWR)

    def pwrite(self, data, offset):
        if not self.writeable():
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))

        with self._lock.shared_context():
            if self._live_md is None:
                raise OSError(errno.EBADF, os.strerror(errno.EBADF))

            return self._live_md.cached_file.pwrite(data, offset)

    def writeable(self):
        return (self._mode & os.O_ACCMODE) in (os.O_WRONLY, os.O_RDWR)

    def _file_length(self):
        return self.stat().size

    def ptruncate(self, offset):
        if not self.writeable():
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))

        with self._lock.shared_context():
            return self._live_md.cached_file.ptruncate(offset)

    def close(self):
        if self.closed:
            return

        with self._lock:
            if self._live_md is None:
                return
            live_md = self._live_md
            self._live_md = None

            toclose = None
            with self._fs._file_cache_lock:
                live_md.open_files.remove(self)
                if (not self._fs._openners and
                    not live_md.open_files and
                    # keep file around as long as its syncing
                    not live_md.cached_file.queue_sync()):
                    toclose = live_md.cached_file
                    popped = self._fs._open_files_by_id.pop(self._id)
                    assert popped is live_md

        if toclose is not None:
            toclose.close()

        super().close()

def check_runtime_requirements():
    if sqlite3.sqlite_version_info < (3, 9, 0):
        raise RuntimeError("Need sqlite version >= 3.9.0, you have: %r" % (sqlite3.sqlite_version,))

class FileSystem(object):
    def __init__(self, fs, cache_folder=None):
        check_runtime_requirements()

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
            assert ("mode=memory" not in self._db_file and
                    ":memory:" not in self._db_file), (
                        "In-memory database connections without " +
                        "shared cache are distinct databases."
                    )

            self._db_lock = None

        self._local = threading.local()

        # NB: at least one conn must be held open if this is an
        #     in-memory DB
        self._conn_thread_stop = threading.Event()
        self._conn_thread_started = threading.Event()
        def conn_thread_start():
            conn = self._init_db()
            self._conn_thread_started.set()
            self._conn_thread_stop.wait()
            conn.close()
        self._conn_thread = threading.Thread(target=conn_thread_start)
        self._conn_thread.start()
        self._conn_thread_started.wait()

        self._file_cache_lock = threading.Lock()
        self._open_files_by_id = {}
        self._openners = 0

        # watch file system and clear cache on any changes
        # NB: we need to use a 'db style' watch because we need the
        #     ids, and create_watch() doesn't promise ids
        try:
            create_db_watch = self._fs.x_create_db_style_watch
        except AttributeError:
            self._watch_stop = None
        else:
            self._watch_stop = create_db_watch(self._handle_changes)

        # start thread that prunes cache
        self._prune_event = threading.Event()
        self._close_prune_thread = False
        threading.Thread(target=self._prune_thread, daemon=True).start()

        # start statvfs caching thread
        self._statvfs_event = threading.Event()
        self._statvfs = None
        threading.Thread(target=self._statvfs_caching_thread, daemon=True).start()

        self._refresh_thread_stop = False
        self._refresh_queue = queue.Queue(100)
        self._refresh_thread = threading.Thread(target=self._refresh_thread_start)
        self._refresh_thread.start()

    def _refresh_thread_start(self):
        while not self._refresh_thread_stop:
            to_refresh = self._refresh_queue.get()
            if to_refresh is None:
                continue

            try:
                with contextlib.closing(self.open_directory(to_refresh)) as dir_:
                    for entry in dir_:
                        if self._refresh_thread_stop:
                            break
                    # If we failed to refresh, re-queue it if we can
                    if not dir_._refreshed:
                        try:
                            self._refresh_queue.put_nowait(to_refresh)
                        except queue.Full:
                            pass
            except OSError:
                pass
            except Exception:
                log.exception("Failed to traverse directory %r", to_refresh)

    def _statvfs_caching_thread(self):
        while not self._close_prune_thread:
            try:
                self._statvfs = self._fs.statvfs()
            except Exception:
                log.warning("Error while calling statvfs", exc_info=True)
            self._statvfs_event.wait()
            self._statvfs_event.clear()

    def close(self):
        if self._close_prune_thread:
            return
        self._close_prune_thread = True
        self._prune_event.set()
        self._conn_thread_stop.set()
        self._conn_thread.join()
        if self._watch_stop is not None:
            self._watch_stop()
        self._refresh_thread_stop = True
        self._refresh_queue.put(None)
        self._refresh_thread.join()
        self._fs.close()

    def _check_space(self, size):
        try:
            vfs_stat = os.statvfs(self._cache_folder)
            free_space = vfs_stat.f_bsize * vfs_stat.f_bavail

            cache_entries = []
            for name in os.listdir(self._cache_folder):
                cache_entries.append((name, os.lstat(os.path.join(self._cache_folder, name))))
        except Exception as e:
            if not isinstance(e, OSError):
                log.exception("Error while checking space")
                return

        cache_size = sum(st.st_size for (_, st) in cache_entries)

        # % of free space that cache is allowed to take up
        N = 0.10

        if (cache_size + size) / (cache_size + free_space) > N:
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    def _prune_thread(self):
        if not self._cache_folder:
            return

        # prune every 30 minutes
        PRUNE_PERIOD = 30 * 60

        while not self._close_prune_thread:
            try:
                # compute total free space on disk
                vfs_stat = os.statvfs(self._cache_folder)
                free_space = vfs_stat.f_bsize * vfs_stat.f_bavail;

                # compute total space taken by cache
                cache_entries = []
                for name in os.listdir(self._cache_folder):
                    cache_entries.append((name, os.lstat(os.path.join(self._cache_folder, name))))

                cache_size = sum(st.st_size for (_, st) in cache_entries)

                # sort by ascending atime, descending size
                cache_entries.sort(key=lambda name_st_pair: -name_st_pair[1].st_size)

                # P: `cache / (cache + free_space)`
                # N: configurable value from [0, 1]

                N = 0.10

                # delete oldest accessed files, largest files until P<=N
                potential_free_space = cache_size + free_space
                for (name, st) in cache_entries:
                    if cache_size / potential_free_space <= N:
                        break

                    try:
                        os.unlink(os.path.join(self._cache_folder, name))
                        cache_size -= st.st_size
                    except Exception:
                        log.exception("Error unlinking file: %r",
                                      os.path.join(self._cache_folder, name))

                self._prune_event.wait(PRUNE_PERIOD)
                self._prune_event.clear()
            except Exception as e:
                if not isinstance(e, OSError):
                    log.exception("Error pruning cache, sleeping...")
                else:
                    log.warning("Error pruning cache, sleeping...", exc_info=True)
                self._prune_event.wait(100)

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

        CREATE TABLE IF NOT EXISTS md_cache_counter
        ( path_key TEXT PRIMARY KEY
        , counter integer NOT NULL
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
        register_deterministic_function(conn, "file_name_norm", 1, wrap_show_exc(self._fs.file_name_norm))
        return conn

    def _get_db_conn(self):
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = self._local.conn = self._create_db_conn()
        return conn

    def _submit_write(self, id_, md):
        if md is not None:
            self._handle_changes([md])

        # Check if file needs to be closed
        toclose = None
        with self._file_cache_lock:
            try:
                live_md = self._open_files_by_id[id_]
            except KeyError:
                # NB: file wasn't open
                return

            if (not self._openners and
                not live_md.open_files and
                # keep file around as long as its syncing
                not live_md.cached_file.queue_sync()):
                toclose = live_md.cached_file
                popped = self._open_files_by_id.pop(id_)
                assert popped is live_md

        if toclose is not None:
            assert not toclose.is_dirty()
            toclose.close()

    def _check_md_cache_entry(self, cursor, path_key):
        cursor.execute("SELECT md FROM md_cache WHERE path_key = ? limit 1",
                       (path_key,))
        row = cursor.fetchone()
        if row is not None:
            (md,) = row
            if md is not None:
                st = json_to_stat(md)
                assert st.type != "file" or st.rev is not None, (
                    "File stat missing rev: %r" % (st,)
                )

    def _update_md(self, cursor, path_key, stat):
        if stat is None:
            md_str = None
        else:
            # if the child is a directory, and we know it hasn't
            # changed (caller guarantee), then do nothing.  this
            # avoids unnecessarily recursively dropping
            # md_cache_entries
            if stat.type == 'directory':
                cursor.execute("SELECT md FROM md_cache WHERE path_key = ? limit 1",
                               (path_key,))
                row = cursor.fetchone()
                if row is not None:
                    (md,) = row
                    if (md is not None and
                        # TODO: doesn't matter for dbxfs child fs, but in the future
                        #       check mtime/size as well
                        getattr(json_to_stat(md), 'type', None) == 'directory'):
                        return
            assert stat.type != "file" or stat.rev is not None, (
                "File stat missing rev: %r" % (stat,)
            )
            md_str = stat_to_json(stat)

        # This is just for debugging
        self._check_md_cache_entry(cursor, path_key)

        cursor.execute("REPLACE INTO md_cache (path_key, md) "
                       "VALUES (?, attr_merge((SELECT md FROM md_cache WHERE path_key = ?), ?))",
                       (path_key, path_key, md_str))

        self._check_md_cache_entry(cursor, path_key)

        # Delete dir entries
        cursor.execute("delete from md_cache_entries where path_key = ?",
                       (path_key,))

        cursor.execute("update md_cache_counter "
                       "set counter = counter + 1 "
                       "where path_key = ?",
                       (path_key,))

    def _reset_metadata_db(self, cursor):
        cursor.execute("DELETE FROM md_cache");
        cursor.execute("DELETE FROM md_cache_entries");
        cursor.execute("update md_cache_counter set counter = counter + 1");

    def _handle_changes(self, changes):
        self._statvfs_event.set()
        conn = self._get_db_conn()
        with trans(conn, self._db_lock, is_exclusive=True):
            cursor = conn.cursor()

            if changes == "reset":
                self._reset_metadata_db(cursor)
                return

            for change in changes:
                # NB: the metadata we currently have could be newer than this change,
                #     so we invalidate cache instead of updating it with stale entry
                # TODO: we need a millisecond-precise 'server_modified' on all metadata
                #       entries from the dropbox api (including
                #       DeletedMetadata and FolderMetadata)

                normed_path = self.create_path(*([] if change.path_lower == "/" else change.path_lower[1:].split("/")))
                self._invalidate_entry(cursor, normed_path)

    def _invalidate_entry(self, cursor, normed_path):
        # if True: if True: here to minimize the diff
        if True:
            if True:
                path_key = str(normed_path.normed())
                parent_path = normed_path.parent
                parent_path_key = str(parent_path)

                # Clear all directory entries,
                # also parent folder entries (since we don't know if
                # this file is currently deleted or not)
                for (path, path_key_) in [
                        (normed_path, path_key),
                        (parent_path, parent_path_key)
                ]:
                    cursor.execute("DELETE FROM md_cache_entries WHERE path_key = ?",
                                   (path_key_,))
                    # if the directory had entries, queue up refresh
                    if cursor.rowcount:
                        try:
                            self._refresh_queue.put_nowait(path)
                        except queue.Full:
                            pass

                # Remove from md cache
                cursor.execute("DELETE FROM md_cache WHERE path_key = ?",
                               (path_key,))

                # Update counters if they existed
                cursor.executemany("update md_cache_counter set counter = counter + 1 "
                                   "where path_key = ?",
                                   [(path_key,), (parent_path_key,)])

    def create_path(self, *args):
        return self._fs.create_path(*args)

    def file_name_norm(self, fn):
        return self._fs.file_name_norm(fn)

    def open(self, path, mode=os.O_RDONLY, directory=False):
        with self._file_cache_lock:
            self._openners += 1
        try:
            st = self.stat(path, create_mode=mode & (os.O_CREAT | os.O_EXCL),
                           directory=directory)

            return _File(self, st, mode)
        finally:
            to_close = []
            with self._file_cache_lock:
                self._openners -= 1

                # close files that have no references
                if not self._openners:
                    for it in self._open_files_by_id.items():
                        (_, live_md) = it
                        if (not live_md.open_files and
                            not live_md.cached_file.queue_sync()):
                            to_close.append(it)

                    for (id_, live_md) in to_close:
                        popped = self._open_files_by_id.pop(id_)
                        assert live_md is popped
            for (_, live_md) in to_close:
                live_md.cached_file.close()

    def open_directory(self, path):
        return _Directory(self, path)

    def stat_has_attr(self, attr):
        return self._fs.stat_has_attr(attr)

    def _get_stat_num(self, cursor, path_key):
        cursor.execute("SELECT counter from md_cache_counter where path_key = ?",
                       (path_key,))
        row = cursor.fetchone()
        if row is None:
            cursor.execute("insert into md_cache_counter "
                           "(path_key, counter) values (?, -1)",
                           (path_key,))
            stat_num = -1
        else:
            (stat_num,) = row
        return stat_num

    def _stat_repeat(self, mutate, path, create_mode, directory,
                     only_cache=False):
        DELETED = object()

        path_key = str(path.normed())
        parent_path_key = str(path.parent.normed())

        conn = self._get_db_conn()

        with trans(conn, self._db_lock, is_exclusive=mutate), contextlib.closing(conn.cursor()) as cursor:
            cursor.execute("SELECT md FROM md_cache WHERE path_key = ? limit 1",
                           (path_key,))
            row = cursor.fetchone()
            if row is None:
                # if it didn't exist in the md_cache, check if the
                # parent exists in md_cache_entries, if so then this
                # file doesn't exist
                (parent_has_been_iterated,) = cursor.execute("""
                SELECT EXISTS(SELECT * FROM md_cache_entries WHERE path_key = ?)
                """, (parent_path_key,)).fetchone()

                if parent_has_been_iterated:
                    stat = DELETED
                else:
                    stat = None
            else:
                (md,) = row
                stat = DELETED if md is None else json_to_stat(md)

            if mutate:
                parent_stat_num = self._get_stat_num(cursor, parent_path_key)
                stat_num = self._get_stat_num(cursor, path_key)

        # If cache says file exists and this is exclusive create,
        # then fail fast. (FUSE effectively works this way too)
        if ((create_mode & os.O_CREAT) and (create_mode & os.O_EXCL) and
            stat is not DELETED and stat is not None):
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST))

        if (((create_mode & os.O_CREAT) and stat is DELETED) or
            stat is None):
            if not mutate:
                return MUST_MUTATE

            try:
                new_stat = self._fs.x_stat_create(path, create_mode, directory)
            except FileNotFoundError:
                new_stat = None

            with trans(conn, self._db_lock, is_exclusive=True), contextlib.closing(conn.cursor()) as cursor:
                # Only update metadata cache the path entry hasn't changed
                # and it's parent hasn't changed
                if (parent_stat_num == self._get_stat_num(cursor, parent_path_key) and
                    stat_num == self._get_stat_num(cursor, path_key)):
                    self._update_md(cursor, path_key, new_stat)

                    (parent_has_been_iterated,) = cursor.execute("""
                    SELECT EXISTS(SELECT * FROM md_cache_entries WHERE path_key = ?)
                    """, (parent_path_key,)).fetchone()

                    if parent_has_been_iterated:
                        # NB: store in parent directory if it is cached
                        if new_stat is not None:
                            cursor.execute("""
                            INSERT OR REPLACE INTO md_cache_entries (path_key, name)
                            SELECT ?, ? WHERE
                            (SELECT EXISTS(SELECT * FROM md_cache_entries WHERE path_key = ?))
                            """, (parent_path_key, path.name, parent_path_key))
                            if cursor.rowcount:
                                # delete directory empty marker if it existed
                                cursor.execute("DELETE FROM md_cache_entries WHERE path_key = ? and name = ?", (parent_path_key, EMPTY_DIR_ENT))
                        else:
                            cursor.execute("""
                            delete from md_cache_entries where path_key = ? and file_name_norm(name) = ?
                            """, (parent_path_key, self._fs.file_name_norm(path.name)))
                            if cursor.rowcount:
                                # insert directory empty marker if there are no more
                                # files under this directory
                                conn.execute("""
                                INSERT INTO md_cache_entries (path_key, name)
                                SELECT ?, ? WHERE
                                (SELECT EXISTS(SELECT * FROM md_cache_entries WHERE
                                path_key = ?)) = 0
                                """,
                                             (parent_path_key, EMPTY_DIR_ENT, parent_path_key))

                        cursor.execute("update md_cache_counter "
                                       "set counter = counter + 1 where "
                                       "path_key = ?",
                                       (parent_path_key,))
                elif create_mode & os.O_CREAT:
                    # If we possibly mutated the fs then we have to at
                    # least invalidate the cache entry.
                    self._invalidate_entry(cursor, path)

            stat = new_stat
        elif stat is DELETED:
            stat = None

        if stat is None:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        elif not only_cache:
            # if the file is currently open, return the currently open stat instead
            with self._file_cache_lock:
                try:
                    md = self._open_files_by_id[stat.id]
                except KeyError:
                    pass
                else:
                    return md.cached_file.stat()

        return stat

    def stat(self, path, create_mode=0, directory=False, only_cache=False):
        mutate = False

        while True:
            res = self._stat_repeat(mutate, path, create_mode, directory,
                                    only_cache=only_cache)
            if res is MUST_MUTATE:
                mutate = True
                continue
            return res

    def fstat(self, fobj):
        return fobj.stat()

    def create_watch(self, cb, handle, *n, **kw):
        # This isinstance is arguably okay because handles are opaque objects
        # returned from open()
        assert isinstance(handle._live_md.cached_file, CachedDirectory)
        return self._fs.create_watch(cb, handle._live_md.cached_file._file, *n, **kw)

    def fsync(self, fobj):
        return fobj.sync()

    def unlink(self, path):
        self._fs.unlink(path)
        md = dropbox.files.DeletedMetadata(name=path.name,
                                           path_lower=str(path.normed()))
        self._handle_changes([md])

    def mkdir(self, path):
        self.stat(path, create_mode=os.O_CREAT | os.O_EXCL, directory=True)

    def rmdir(self, path):
        self._fs.rmdir(path)
        md = dropbox.files.DeletedMetadata(name=path.name,
                                           path_lower=str(path.normed()))
        self._handle_changes([md])

    def rename_noreplace(self, oldpath, newpath):
        self._fs.rename_noreplace(oldpath, newpath)
        old_path_norm = str(oldpath.normed())
        new_path_norm = str(newpath.normed())

        # Invalidate cache entries for old path tree, and new path
        conn = self._get_db_conn()
        with trans(conn, self._db_lock, is_exclusive=True), contextlib.closing(conn.cursor()) as cursor:
            # TODO: send renamed directories to _refresh_thread

            # Clear new path's, new path's parent's, and old path's parent's entries
            cursor.executemany("DELETE FROM md_cache_entries WHERE path_key = ?",
                               [(new_path_norm,), (str(newpath.parent.normed()),),
                                (str(oldpath.parent.normed()),)])

            # Clear new path
            cursor.execute("DELETE FROM md_cache WHERE path_key = ?",
                           (new_path_norm,))

            cursor.executemany("update md_cache_counter set counter = counter + 1 "
                               "where path_key = ?",
                               [(new_path_norm,), (str(newpath.parent.normed()),),
                                (str(oldpath.parent.normed()),)])

            # Clear all old children's entries
            cursor.execute("DELETE FROM md_cache_entries "
                           "WHERE path_key = ? or path_key like ? || '/%'",
                           (old_path_norm, old_path_norm,))

            # Clear all old children
            cursor.execute("DELETE FROM md_cache WHERE path_key = ? or path_key like ? || '/%'",
                           (old_path_norm, old_path_norm,))
            cursor.execute("update md_cache_counter set counter = counter + 1 "
                           "where path_key = ? or path_key like ? || '/%'",
                           (old_path_norm, old_path_norm,))

    def statvfs(self):
        if self._statvfs is None:
            vfs = quick_container(f_frsize=DOWNLOAD_UNIT,
                                  f_blocks=0,
                                  f_bavail=0)
        else:
            vfs = self._statvfs
        return quick_container(f_frsize=DOWNLOAD_UNIT,
                               f_blocks=(vfs.f_blocks * vfs.f_frsize) // DOWNLOAD_UNIT,
                               f_bavail=(vfs.f_bavail * vfs.f_frsize) // DOWNLOAD_UNIT)

    def pread(self, handle, size, offset):
        return handle.pread(size, offset)

    def pwrite(self, handle, data, offset):
        return handle.pwrite(data, offset)

    def ftruncate(self, handle, offset):
        return handle.ptruncate(offset)

def main(argv):
    logging.basicConfig(level=logging.DEBUG)

    # This runtime import is okay because it happens in main()
    from userspacefs.memoryfs import FileSystem as MemoryFileSystem

    backing_fs = MemoryFileSystem([("foo", {"type": "directory",
                                            "children" : [
                                                ("baz", {"type": "file", "data": b"YOOOO"}),
                                                ("quux", {"type": "directory"}),
                                            ]
                                        }),
                                   ("bar", {"type": "file", "data": b"f"})])

    tmp_dir = tempfile.mkdtemp()
    fs = None
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

        # now write to a file
        with contextlib.closing(fs.open(fs.create_path("bar"), os.O_RDWR)) as f:
            f.read()
            f.write(b"hi")
            fs.fsync(f)
            f.seek(0)
            contents = f.read()
            if contents != b"fhi":
                print("Contents of bar:", contents, "(should be 'fhi')")
                return 1

        with contextlib.closing(fs.open(fs.create_path("bar"))) as f:
            contents = f.read()
            if contents != b"fhi":
                print("Contents of bar:", contents, "(should be 'fhi')")
                return 1

        # now create new file
        with contextlib.closing(fs.open(fs.create_path("newcrazy"),
                                        os.O_CREAT | os.O_WRONLY)) as f:
            f.write(b'test')

        try:
            with contextlib.closing(fs.open(fs.create_path("newcrazy"),
                                            os.O_CREAT | os.O_EXCL)) as f:
                pass
        except FileExistsError:
            # should throw
            pass
        else:
            raise Exception("Didn't throw on EXCL!")

        with contextlib.closing(fs.open(fs.create_path("newcrazy"),
                                        os.O_CREAT | os.O_RDONLY)) as f:
            print("Contents of bar:", f.read(), "(should be 'test')")

        fs.unlink(fs.create_path("newcrazy"))

        try:
            with contextlib.closing(fs.open(fs.create_path("newcrazy"))) as f:
                print("Contents of bar:", f.read(), "(should be '')")
        except FileNotFoundError:
            pass
        else:
            raise Exception("Didn't throw on file not found!!")

        fs.mkdir(fs.create_path("newdir"))

        try:
            fs.mkdir(fs.create_path("newdir"))
        except FileExistsError:
            pass
        else:
            raise Exception("Didn't throw file exists error!!")

        with fs.open(fs.create_path("newdir", "test-file"), os.O_CREAT | os.O_WRONLY) as f:
            f.write(b"TEST AGAIN")

        with fs.open(fs.create_path("newdir", "test-file")) as f:
            print("Contents of newdir/test-file: %r (should be b'TEST AGAIN')" %
                  (f.read(),))

        try:
            fs.rmdir(fs.create_path("newdir"))
        except OSError as e:
            if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                # Not expected
                raise
        else:
            raise Exception("Expected not empty error")

        fs.unlink(fs.create_path("newdir", "test-file"))
        fs.rmdir(fs.create_path("newdir"))

        root_path = fs.create_path()
        file_path_4 = root_path.joinpath("dbfs-test-file.txt")

        with fs.open(file_path_4, os.O_CREAT) as f:
            pass

        file_path_5 = file_path_4.parent.joinpath("dbfs-test-file-2.txt")

        try:
            fs.unlink(file_path_5)
        except FileNotFoundError:
            pass

        fs.rename_noreplace(file_path_4, file_path_5)

        try:
            with fs.open(file_path_4) as f:
                pass
        except FileNotFoundError:
            # expected
            pass
        else:
            raise Exception("expected file not found error!")

        fs.unlink(file_path_5)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        if fs is not None:
            fs.close()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
