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
    def __init__(self, fs, path):
        self._fs = fs
        self._path = path
        self._offset = 0

    def pread(self, offset, size=-1):
        if str(self._path) == '/':
            raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))
        try:
            with self._fs._client.get_file(str(self._path), start=offset,
                                       length=size if size >= 0 else None) as resp:
                return resp.read()
        except dropbox.rest.ErrorResponse as e:
            if e.error_msg == "Path is a directory":
                raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))
            else: raise

    def read(self, size=-1):
        toret = self.pread(offset, size)
        self._offset += toret
        return toret

    def readall(self):
        return self.read()

Change = collections.namedtuple('Change', ['action', 'filename'])

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
    url, params, headers = dbfs._client.request("/delta/latest_cursor", {})
    res = dbfs._client.rest_client.POST(url, params, headers)
    cursor = res['cursor']
    while True:
        try:
            res = dbfs._client.delta(cursor=cursor)
        except:
            log.exception()
            # TODO: this should be exponential backoff
            time.sleep(60)
            continue

        with dbfs._watches_lock:
            watches = list(dbfs._watches)

        for (cb, dir_handle, completion_filter, watch_tree) in watches:
            if res['reset']:
                cb('reset')

            # TODO: filter based on completion filter

            # XXX: we don't check if the directory has been moved
            to_sub = []
            ndirpath = str(dir_handle._path).lower()
            prefix_ndirpath = ndirpath + ("" if ndirpath == "/" else "/")
            for (path, md) in res['entries']:
                log.debug("PATH %r %r", path, md)
                if not path.lower().startswith(prefix_ndirpath):
                    continue
                if (not watch_tree and
                    path.lower()[len(prefix_ndirpath):].find("/") != -1):
                    continue
                basename = path.lower()[len(prefix_ndirpath):]
                # TODO: pull initial directory entries to tell the difference
                #       "added" and "modified"
                action = ("removed"
                          if md is None else
                          "modified")
                to_sub.append(Change(action, basename))

            try:
                cb(to_sub)
            except:
                log.exception()

        cursor = res['cursor']
        if not res['has_more']:
            while True:
                try:
                    resp = dbfs._client.longpoll_delta(cursor)
                except:
                    log.exception()
                    break
                if resp.get('changes', False): break
                backoff = resp.get('backoff', 0)
                if backoff:
                    time.sleep(backoff)

class FileSystem(object):
    def __init__(self, access_token):
        self._access_token = access_token
        self._local = threading.local()
        self._watches = []
        self._watches_lock = threading.Lock()

        # kick off delta thread
        threading.Thread(target=delta_thread, args=(self,), daemon=True).start()

    def close(self):
        # TODO: send signal to stop delta_thread
        pass

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
        return _File(self, path)

    def open_directory(self, path):
        return _Directory(self, path)

    def stat_has_attr(self, attr):
        return attr in ["type", "size", "mtime"]

    def stat(self, path):
        return self._get_md(path)

    def fstat(self, fobj):
        return self._get_md(fobj._path)

    def create_watch(self, cb, dir_handle, completion_filter, watch_tree):
        # NB: current MemoryFS is read-only so
        #     cb will never be called and stop() can
        #     be a no-op
        if not isinstance(dir_handle, _File):
            raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))

        tag = (cb, dir_handle, completion_filter, watch_tree)

        with self._watches_lock:
            self._watches.append(tag)

        def stop():
            with self._watches_lock:
                self._watches.remove(tag)

        return stop
