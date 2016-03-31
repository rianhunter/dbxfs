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

import codecs
import collections
import contextlib
import datetime
import errno
import http
import io
import itertools
import json
import logging
import os
import threading
import time
import ssl
import sys
import urllib
import urllib.request

import dropbox

from dropboxfs.path_common import Path

log = logging.getLogger(__name__)

def md_to_stat(md):
    _StatObject = collections.namedtuple("Stat", ["name", "type", "size", "mtime", "id", "ctime"])
    name = md.name
    type = 'directory' if isinstance(md, dropbox.files.FolderMetadata) else 'file'
    size = 0 if isinstance(md, dropbox.files.FolderMetadata) else md.size
    mtime = (md.client_modified
             if not isinstance(md, dropbox.files.FolderMetadata) else
             datetime.datetime.utcnow())
    ctime = getattr(md, 'server_modified', datetime.datetime.utcnow())
    return _StatObject(name, type, size, mtime, md.id, ctime=ctime)

class _Directory(object):
    def __init__(self, fs, path, id_):
        self._fs = fs
        self._path = path
        self._id = id_
        self.reset()

    def __it(self):
        # XXX: Hack: we "snapshot" this directory by not returning entries
        #      newer than the moment this iterator was started
        start = datetime.datetime.utcnow()
        self._cursor = None
        stop = False
        while not stop:
            if self._cursor is None:
                path_ = "" if self._path == "/" else self._path
                res = self._fs._clientv2.files_list_folder(path_)
            else:
                res = self._fs._clientv2.files_list_folder_continue(self._cursor)

            for f in res.entries:
                if isinstance(f, dropbox.files.DeletedMetadata):
                    continue
                if (isinstance(f, dropbox.files.FileMetadata) and
                    f.server_modified > start):
                    stop = True
                    break
                yield md_to_stat(f)

            self._cursor = res.cursor

            if not res.has_more:
                stop = True

    def read(self):
        try:
            return next(self)
        except StopIteration:
            return None

    def readmany(self, size=None):
        if size is None:
            return list(self)
        else:
            return list(itertools.islice(self, size))

    def reset(self):
        self._md = self.__it()

    def close(self):
        pass

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._md)

class DropboxAPIError(Exception):
    def __init__(self, json_):
        super().__init__(json_)

def download_connection(access_token, path, start=None, length=None):
    target_host_port = ("content.dropboxapi.com", 443)

    ssl_context = ssl.create_default_context()
    ca_bundle = os.getenv("REQUESTS_CA_BUNDLE")
    if ca_bundle is not None:
        ssl_context.load_verify_locations(ca_bundle)

    proxy = os.getenv("HTTPS_PROXY")
    if proxy is not None:
        o = urllib.parse.urlparse(proxy)
        conn = http.client.HTTPSConnection(o.hostname, o.port, context=ssl_context)
        conn.set_tunnel(*target_host_port)
    else:
        conn = http.client.HTTPSConnection(*target_host_port, context=ssl_context)

    args = {"path" : path}

    path = "/2/files/download?" + urllib.parse.urlencode({'arg' : json.dumps(args)})

    headers = {}
    headers['Authorization'] = 'Bearer {}'.format(access_token)

    if start is not None:
        if length is not None:
          headers['Range'] = 'bytes=%s-%s' % (start, start + length - 1)
        else:
          headers['Range'] = 'bytes=%s-' % start
    elif length is not None:
        headers['Range'] = 'bytes=-%s' % length

    conn.request("GET", path, None, headers)
    resp = conn.getresponse()

    if resp.status == 409:
        reader = codecs.getreader("utf-8")
        error = json.load(reader(resp))
        raise DropboxAPIError(error)
    elif resp.status not in (200, 206):
        data = resp.read()
        raise Exception("HTTPError %r %r" % (resp.status, data))

    md = json.loads(resp.getheader("dropbox-api-result"))

    return (md, resp)

class _File(io.RawIOBase):
    def __init__(self, fs, id_):
        self._fs = fs
        self._id = id_
        self._offset = 0
        self._lock = threading.Lock()
        self._read_conn = None
        self._rev = None
        self._read_conn_is_invalid = True

    def pread(self, offset, size=-1):
        # NB: We don't use self._read_conn to avoid locking
        #     since pread() is usually parallel-friendly

        try:
            (md, resp) = download_connection(self._fs._access_token, self._id,
                                             start=offset,
                                             length=None if size < 0 else size)

            range_was_honored = resp.getheader("content-range")

            if not range_was_honored:
                log.warning("Range wasn't honored: %r", (offset, size))

            # NB: pread() may restart file download
            #     this is so we never can read() something older
            #     that what we pread() previously
            self._read_conn_is_invalid = md['rev'] != self._rev

            with contextlib.closing(resp):
                bufs = []
                if range_was_honored:
                    while True:
                        c = resp.read(2 ** 16)
                        if not c: break
                        bufs.append(c)
                else:
                    # handle case where range isn't honored because
                    # offset is past the EOF
                    content_length = resp.getheader('content-length')
                    if (content_length is not None and
                        offset >= int(content_length)):
                        return b''

                    cur_offset = 0
                    bufs_len = 0
                    while True:
                        c = resp.read(2 ** 16)
                        if not c: break
                        bufs.append(c[max(0, offset - cur_offset):
                                      min(len(c), (offset + size - cur_offset
                                                   if size >= 0 else
                                                   len(c)))])
                        bufs_len += len(bufs[-1])
                        assert size < 0 or bufs_len <= size
                        if size >= 0 and bufs_len == size:
                            break
                        cur_offset += len(c)
                return b''.join(bufs)
        except DropboxAPIError as e:
            if (e.args[0]['error']['.tag'] == "path" and
                e.args[0]['error']['path']['.tag'] == "not_file"):
                raise OSError(errno.EISDIR, os.strerror(errno.EISDIR)) from None
            else: raise

    def _restart_read_conn(self):
        if self._read_conn is not None:
            self._read_conn.close()

        (md, self._read_conn) = self._fs._clientv2.files_download(self._id)
        self._rev = md.rev
        stat = md_to_stat(md)

        # now skip those bytes
        toread = self._offset
        while toread:
            r = self._read_conn.raw.read(min(toread, 2 ** 16))
            toread -= len(r)

        return stat

    def _seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_CUR:
            if offset < 0:
                self._offset += offset
                whence = io.SEEK_SET
            else:
                if self._read_conn_is_invalid:
                    self._restart_read_conn()
                    self._read_conn_is_invalid = False
                # just skip the requested amount of bytes
                toread = offset
                while toread:
                    r = self._read_conn.raw.read(min(toread, 2 ** 16))
                    toread -= len(r)
                    self._offset += len(r)
                return

        if whence != io.SEEK_SET:
            raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

        if self._offset == offset:
            return

        self._offset = offset
        self._restart_read_conn()

    def seek(self, *n, **kw):
        with self._lock:
            return self._seek(*n, **kw)

    def readinto(self, buf):
        with self._lock:
            if self._read_conn_is_invalid:
                self._restart_read_conn()
                self._read_conn_is_invalid = False
            toret = self._read_conn.raw.readinto(buf)
            self._offset += toret
            return toret

    def writable(self):
        return False

    def readable(self):
        return True

    def seekable(self):
        return True

    def close(self):
        if self._read_conn is not None:
            self._read_conn.close()

    def stat(self):
        with self._lock:
            if self._read_conn is not None:
                md = self._fs._get_md_inner(self._id)
                # Restart read conn if this stat is newer
                self._read_conn_is_invalid = md.rev != self._rev
                return md_to_stat(md)
            else:
                # NB: This is optimized for the case when an fstat()
                #     is done before any reading.
                #     => only a single request is made
                assert not self._offset and self._read_conn_is_invalid, \
                    ("There should be no instance when offset "
                     "is non-zero or read_conn_is_invalid is false "
                     "and read_conn is None")
                toret = self._restart_read_conn()
                self._read_conn_is_invalid = False
                return toret

Change = collections.namedtuple('Change', ['action', 'path'])

(FILE_NOTIFY_CHANGE_FILE_NAME,
 FILE_NOTIFY_CHANGE_DIR_NAME,
 FILE_NOTIFY_CHANGE_ATRIBUTES,
 FILE_NOTIFY_CHANGE_SIZE,
 FILE_NOTIFY_CHANGE_LAST_WRITE,
 FILE_NOTIFY_CHANGE_LAST_ACCESS,
 FILE_NOTIFY_CHANGE_CREATION,
 FILE_NOTIFY_CHANGE_EA,
 FILE_NOTIFY_CHANGE_SECURITY,
 FILE_NOTIFY_CHANGE_STREAM_NAME,
 FILE_NOTIFY_CHANGE_STREAM_SIZE,
 FILE_NOTIFY_CHANGE_STREAM_WRITE) = map(lambda x: 1 << x, range(12))

def delta_thread(dbfs):
    cursor = None
    needs_reset = True
    while True:
        try:
            if cursor is None:
                cursor = dbfs._clientv2.files_list_folder_get_latest_cursor('', True).cursor
            res = dbfs._clientv2.files_list_folder_continue(cursor)
        except Exception as e:
            if isinstance(e, dropbox.files.ListFolderContinueError):
                cursor = None
                needs_reset = True

            log.exception("failure while doing list folder")
            # TODO: this should be exponential backoff
            time.sleep(60)
            continue

        with dbfs._watches_lock:
            watches = list(dbfs._watches)

        for watch in watches:
            if needs_reset:
                watch('reset')
            watch(res.entries)

        needs_reset = False

        cursor = res.cursor
        if not res.has_more:
            try:
                while True:
                    res = dbfs._clientv2.files_list_folder_longpoll(cursor)
                    if res.changes:
                        break
                    if res.backoff is not None:
                        time.sleep(res.backoff)
            except:
                log.exception("failure during longpoll")

class FileSystem(object):
    def __init__(self, access_token):
        self._access_token = access_token
        self._local = threading.local()
        self._watches = []
        self._watches_lock = threading.Lock()

        # share this session (i.e. connection pool) across threads
        self._db_session = dropbox.create_session()

        # kick off delta thread
        threading.Thread(target=delta_thread, args=(self,), daemon=True).start()

    def _add_watch(self, watch_fn):
        with self._watches_lock:
            self._watches.append(watch_fn)

    def _remove_watch(self, watch_fn):
        with self._watches_lock:
            self._watches.remove(watch_fn)

    def close(self):
        # TODO: send signal to stop delta_thread
        pass

    def create_path(self, *args):
        return Path.root_path().joinpath(*args)

    def parse_path(self, p):
        return Path.parse_path(p)

    # NB: This is probably evil opaque magic
    @property
    def _clientv2(self):
        toret = getattr(self._local, '_clientv2', None)
        if toret is None:
            self._local._clientv2 = toret = dropbox.Dropbox(self._access_token,
                                                            session=self._db_session)
        return toret

    def _get_md_inner(self, path):
        log.debug("GET %r", path)
        try:
            # NB: allow for raw paths/id strings
            p = str(path)
            if p == '/':
                return dropbox.files.FolderMetadata(name="/", path_lower="/", id="/")
            md = self._clientv2.files_get_metadata(p)
        except dropbox.exceptions.ApiError as e:
            if e.error.is_path():
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
            else: raise
        return md

    def _get_md(self, path):
        md = self._get_md_inner(path)
        log.debug("md: %r", md)
        return md_to_stat(md)

    def open(self, path):
        md = self._get_md_inner(path)
        return _File(self, md.id)

    def open_by_id(self, id_):
        return _File(self, id_)

    def open_directory(self, path):
        md = self._get_md_inner(path)
        return _Directory(self, md.path_lower, md.id)

    def stat_has_attr(self, attr):
        return attr in ["type", "size", "mtime", "id"]

    def stat(self, path):
        return self._get_md(path)

    def fstat(self, fobj):
        return fobj.stat()

    def create_watch(self, cb, dir_handle, completion_filter, watch_tree):
        # TODO: we don't support added, moved_from, or moved_to events

        if not isinstance(dir_handle, _File):
            raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))

        id_ = dir_handle._id
        dirpath = [None]
        done = [False]

        def watch_fn(entries):
            if entries == "reset":
                return cb("reset")

            process_delete = True
            if dirpath[0] is None:
                process_delete = False
                if id_ == "/":
                    dirpath[0] = id_
                else:
                    md = self._get_md_inner(id_)
                    dirpath[0] = md.path_lower

            to_sub = []
            ndirpath = dirpath[0]
            prefix_ndirpath = ndirpath + ("" if ndirpath == "/" else "/")

            for entry in entries:
                # XXX: this check is racy since this could be a stale
                #      delete from before we event retrieved the ID
                #      for this file. We minimize damage using
                #      `process_delete` but there is still chance of
                #      us getting stale data the next time we are
                #      called (though this should rarely occur in
                #      practice).
                if (process_delete and
                    isinstance(entry, dropbox.files.DeletedMetadata) and
                    entry.path_lower == ndirpath):
                    done[0] = True
                    continue

                if (not isinstance(entry, dropbox.files.DeletedMetadata) and
                    entry.id == id_):
                    dirpath[0] = md.path_lower
                    ndirpath = dirpath[0]
                    prefix_ndirpath = ndirpath + ("" if ndirpath == "/" else "/")
                    done[0] = False

                if done[0]:
                    continue

                # TODO: filter based on completion filter
                if not entry.path_lower.startswith(prefix_ndirpath):
                    continue
                if (not watch_tree and
                    entry.path_lower[len(prefix_ndirpath):].find("/") != -1):
                    continue
                path = self.create_path(*(([] if ndirpath == "/" else ndirpath[1:].split("/")) +
                                          [entry.name]))

                # TODO: pull initial directory entries to tell the difference
                #       "added" and "modified"
                action = ("removed"
                          if isinstance(entry, dropbox.files.DeletedMetadata) else
                          "modified")
                to_sub.append(Change(action, path))

            if to_sub:
                try:
                    cb(to_sub)
                except:
                    log.exception("failure during watch callback")

        self._add_watch(watch_fn)

        def stop():
            self._remove_watch(watch_fn)

        return stop

    def create_db_style_watch(self, cb):
        self._add_watch(cb)

        def stop():
            self._remove_watch(cb)

        return stop

def main(argv):
    # run some basic tests on this class

    with open(os.path.expanduser("~/.dropboxfs")) as f:
        token = json.load(f)['access_token']

    fs = FileSystem(token)

    root_path = fs.create_path()

    root_md = fs.stat(root_path)
    print("Root MD:", root_md)

    print("Root directory listting:")
    with contextlib.closing(fs.open_directory(root_path)) as f:
        for entry in f:
            if entry.type == "file":
                to_open = entry
            print("", entry)

    file_path = root_path.joinpath(to_open.name)
    file_md = fs.stat(file_path)
    print("File MD:", file_md)

    with contextlib.closing(fs.open(file_path)) as f:
        print("File Data: %r" % (f.read(4),))
        print("File Data 2: %r" % (f.read(4),))

    event = threading.Event()
    def cb(changes):
        print(changes)
        event.set()

    with contextlib.closing(fs.open(root_path)) as root:
        stop = fs.create_watch(cb, root, ~0, False)
        print("Waiting for FS event for 10 seconds")
        event.wait(5 * 60)
        stop()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
