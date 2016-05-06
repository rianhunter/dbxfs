import contextlib
import datetime
import errno
import itertools
import logging
import os
import random
import threading
import stat
import sys

from fuse import FUSE

from dropboxfs.util_dumpster import utctimestamp

log = logging.getLogger(__name__)

# Can't derive from fuse.Operations because Finder will
# fail to copy if getxattr() returns ENOTSUP, better to
# not implement it at all
class FUSEAdapter(object):
    flag_nopath = 1

    def __init__(self, create_fs):
        self._create_fs = create_fs
        self._fh_to_file = {}
        self._lock = threading.Lock()

    def _save_file(self, f):
        with self._lock:
            while True:
                r = random.randint(0, 2 ** 32 - 1)
                if r not in self._fh_to_file:
                    break
            self._fh_to_file[r] = f
            return r

    def _delete_file(self, fh):
        with self._lock:
            return self._fh_to_file.pop(fh)

    def _conv_path(self, path):
        toret = self._fs.create_path()
        if path == '/':
            return toret
        return toret.joinpath(*path[1:].split('/'))

    def _fs_stat_to_fuse_attrs(self, st):
        toret = {}

        toret['st_birthtime'] = utctimestamp(getattr(st, "birthtime", datetime.datetime.utcfromtimestamp(0)))
        toret['st_mtime'] = utctimestamp(getattr(st, "mtime", datetime.datetime.utcfromtimestamp(toret['st_birthtime'])))
        toret['st_ctime'] = utctimestamp(getattr(st, "ctime", datetime.datetime.utcfromtimestamp(toret['st_mtime'])))
        toret['st_atime'] = utctimestamp(getattr(st, "atime", datetime.datetime.utcfromtimestamp(toret['st_ctime'])))

        toret['st_size'] = st.size

        toret['st_mode'] = ((stat.S_IFDIR | 0o777)
                            if st.type == 'directory' else
                            (stat.S_IFREG | 0o666))

        # NB: st_nlink on directories is really inconsistent across filesystems
        #     and OSes. it arguably doesn't matter at all but we set it to
        #     non-zero just in case
        toret['st_nlink'] = 1
        toret['st_uid'] = os.getuid()
        toret['st_gid'] = os.getgid()

        return toret

    def init(self, _):
        self._fs = self._create_fs()

    def getattr(self, path, fh=None):
        if fh is not None:
            if fh not in self._fh_to_file:
                raise Exception("Fuse passed us invalid file handle!: %r" % (fh,))
            st = self._fs.fstat(self._fh_to_file[fh])
        else:
            st = self._fs.stat(self._conv_path(path))
        return self._fs_stat_to_fuse_attrs(st)

    def create(self, path, mode):
        return self._save_file(self._fs.open(self._conv_path(path),
                                             os.O_WRONLY | os.O_CREAT))

    def open(self, path, flags):
        return self._save_file(self._fs.open(self._conv_path(path), flags))

    def read(self, path, size, offset, fh):
        f = self._fh_to_file[fh]
        return f.pread(offset, size)

    def write(self, path, data, offset, fh):
        f = self._fh_to_file[fh]
        return f.pwrite(data, offset)

    def truncate(self, path, length, fh=None):
        if fh is None:
            # TODO: add truncate() call to FS interface
            with contextlib.closing(self._fs.open(self._conv_path(path), os.O_WRONLY)) as f:
                f.ptruncate(length)
        else:
            f = self._fh_to_file[fh]
            f.ptruncate(length)

    def fsync(self, path, datasync, fh):
        self._fs.fsync(self._fh_to_file[fh])
        return 0

    def release(self, path, fh):
        self._delete_file(fh).close()
        return 0

    def opendir(self, path):
        return self._save_file(self._fs.open_directory(self._conv_path(path)))

    def readdir(self, path, fh):
        # TODO: pyfuse doesn't expose a better interface for large directories
        f = self._fh_to_file[fh]
        return list(itertools.chain(['.', '..'], map(lambda x: (x.name, self._fs_stat_to_fuse_attrs(x), 0), f)))

    def releasedir(self, path, fh):
        self._delete_file(fh).close()

    def unlink(self, path):
        self._fs.unlink(self._conv_path(path))

    def mkdir(self, path, mode):
        self._fs.mkdir(self._conv_path(path))

    def rmdir(self, path):
        self._fs.rmdir(self._conv_path(path))

    def rename(self, oldpath, newpath):
        oldpath_ = self._conv_path(oldpath)
        newpath_ = self._conv_path(newpath)
        while True:
            try:
                self._fs.rename_noreplace(oldpath_, newpath_)
            except FileExistsError:
                try:
                    self._fs.unlink(newpath_)
                except FileNotFoundError:
                    pass
            else:
                break

    def chmod(self, path, mode):
        return 0

    def utimens(self, path, times=None):
        return 0

    def statfs(self, _):
        vfs = self._fs.statvfs()
        toret = {}
        for n in ['f_bavail', 'f_blocks', 'f_frsize']:
            toret[n] = getattr(vfs, n)

        toret['f_bfree'] = toret['f_bavail']
        toret['f_bsize'] = toret['f_frsize']

        return toret

    def __call__(self, op, *args):
        return getattr(self, op)(*args)

def run_fuse_mount(create_fs, mount_point, foreground=False, display_name=None, fsname=None):
    kw = {}
    if sys.platform == 'darwin':
        kw['volname'] = display_name
    FUSE(FUSEAdapter(create_fs), mount_point, foreground=foreground, hard_remove=True,
         default_permissions=True, fsname=fsname, **kw)
