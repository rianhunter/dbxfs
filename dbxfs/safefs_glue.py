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

import base64
import collections
import contextlib
import errno
import os
import json
import subprocess

from userspacefs.path_common import Path

from safefs import console_init_safefs, FileSystem as SafeFileSystem

Change = collections.namedtuple('Change', ['action', 'path'])

class ChrootFileSystem(object):
    def __init__(self, fs, new_root):
        self._fs = fs
        self._new_root = new_root

    def create_path(self, *args):
        return self._new_root.joinpath(*args)

    def __getattr__(self, n):
        return getattr(self._fs, n)

    def close(self):
        # Don't close self._fs, since the SubFileSystem closes the root
        pass

class WrappedFile(object):
    def __init__(self, fs, handle):
        self._fs = fs
        self._handle = handle

    def stat(self):
        return self._fs.fstat(self._handle)

    def create_watch(self, cb, completion_filter, watch_tree):
        return self._fs.create_watch(cb, self._handle, completion_filter, watch_tree)

    def pread(self, *n):
        return self._fs.pread(self._handle, *n)

    def pwrite(self, *n):
        return self._fs.pwrite(self._handle, *n)

    def ptruncate(self, *n):
        return self._fs.ftruncate(self._handle, *n)

    def sync(self):
        return self._fs.fsync(self._handle)

    def x_set_file_times(self, *n):
        return self._fs.x_f_set_file_times(self._handle, *n)

    def __getattr__(self, n):
        return getattr(self._handle, n)

# NB: this class is not as general as it sounds
#     at minimum it requires:
#     1) each subfs has the same statvfs() as the parent
#     2) each subfs normalizes file names the same way
#     3) x_f_set_file_times() to be consistently implemented
#     it probably requires other things as well, userspacefs was not
#     meant to generally host mounted file systems
class SubFileSystem(object):
    def __init__(self, fs, subs):
        self._fs = fs
        self._subfs = dict(subs)

        def x_f_set_file_times(handle, *n):
            return handle.x_set_file_times(*n)

        if hasattr(self._subfs, 'x_f_set_file_times'):
            self.x_f_set_file_times = x_f_set_file_times

    def close(self):
        if self._fs is None:
            return
        for subfs in self._subfs.values():
            subfs.close()
        self._fs.close()
        self._fs = None

    def create_path(self, *args):
        return Path(args, fn_norm=self._fs.file_name_norm)

    def _transform_path(self, p):
        fs = self._fs
        root = fs.create_path()

        for n in p.parts[1:]:
            if fs is self._fs and root in self._subfs:
                fs = self._subfs[root]
                root = fs.create_path()
            root = root / n

        if fs is self._fs and root in self._subfs:
            fs = self._subfs[root]
            root = fs.create_path()

        return (fs, root)

    def open(self, path, *n, **kw):
        (fs, path) = self._transform_path(path)
        return WrappedFile(fs, fs.open(path, *n, **kw))

    def open_directory(self, path):
        (fs, path) = self._transform_path(path)
        return fs.open_directory(path)

    def stat_has_attr(self, attr):
        # stat_has_attr needs to know if stat call could return attr
        # it's okay if it doesn't
        val = self._fs.stat_has_attr(attr)
        for fs in self._subfs.values():
            val = val or self._fs.stat_has_attr(attr)
        return val

    def stat(self, path):
        (fs, path) = self._transform_path(path)
        return fs.stat(path)

    def fstat(self, handle):
        return handle.stat()

    def create_watch(self, cb, dir_handle, completion_filter, watch_tree):
        if watch_tree:
            raise NotImplementedError("Can't implement this!")
        return dir_handle.create_watch(cb, completion_filter, watch_tree)

    def unlink(self, path):
        (fs, path) = self._transform_path(path)
        return fs.unlink(path)

    def mkdir(self, path):
        (fs, path) = self._transform_path(path)
        return fs.mkdir(path)

    def rmdir(self, path):
        (fs, path) = self._transform_path(path)
        return fs.rmdir(path)

    def rename_noreplace(self, old_path, new_path):
        (fs1, old_path) = self._transform_path(old_path)
        (fs2, new_path) = self._transform_path(new_path)
        if fs1 is not fs2:
            raise OSError(errno.EXDEV, os.strerror(errno.EXDEV))
        return fs1.rename_noreplace(old_path, new_path)

    def statvfs(self):
        return self._fs.statvfs()

    def pread(self, handle, size, offset):
        return handle.pread(size, offset)

    def pwrite(self, handle, data, offset):
        return handle.pwrite(data, offset)

    def ftruncate(self, handle, offset):
        return handle.ptruncate(offset)

    def fsync(self, handle):
        return handle.sync()

def enc_folder_to_path(fs, enc_folder):
    return fs.create_path(*(enc_folder.split('/')))

class EncryptedFSFactory(object):
    def __init__(self, create_fs, keys):
        self._create_fs = create_fs
        self._keys = keys

    def __call__(self):
        fs = self._create_fs()

        subs = []
        for (enc_folder, (md, master_key)) in self._keys:
            root = enc_folder_to_path(fs, enc_folder)
            subs.append((root,
                         SafeFileSystem(ChrootFileSystem(fs, root), md, master_key)))

        del self._keys

        return SubFileSystem(fs, subs)

def safefs_add_fs_args(fs, encrypted_folders, fs_args):
    if not encrypted_folders:
        return

    keys = []
    if True:
        # if any of the encrypted folders is a descendent of
        # another one, then fail
        folders = set()
        parents = set()
        for enc_folder_md in encrypted_folders:
            enc_folder = enc_folder_md["path"]

            root = enc_folder_to_path(fs, enc_folder)

            # check if we already encrypting a child
            if root in parents:
                raise ValueError("Can't have nested encrypted folders")

            p = root
            while p.parent != p:
                p = p.parent
                if p in folders:
                    raise ValueError("Can't have nested encrypted folders")
                parents.add(p)

            folders.add(root)

        for enc_folder_md in encrypted_folders:
            enc_folder = enc_folder_md["path"]

            pass_ = None
            password_command = enc_folder_md.get("password_command")
            if password_command is not None:
                print("Running %r to retrieve password for %r" % (' '.join(password_command), enc_folder))
                with subprocess.Popen(password_command, stdout=subprocess.PIPE) as proc:
                    pass_ = proc.stdout.read()
                    if proc.wait():
                        raise Exception("Password command for %s failed: %s" % (
                            enc_folder,
                            ' '.join(password_command),
                        ))
            else:
                print("Setup for encrypted %r..." % (enc_folder,))

            root = enc_folder_to_path(fs, enc_folder)
            key = console_init_safefs(fs, root, pass_=pass_)
            if key is None:
                continue
            keys.append((enc_folder, key))

    def encode_bytes(obj):
        if not isinstance(obj, bytes):
            raise TypeError()

        return {'__bytes__': True, 'data': base64.b64encode(obj).decode("utf-8")}

    fs_args['safefs_keys'] = json.dumps(keys, default=encode_bytes)

def safefs_wrap_create_fs(create_fs, fs_args):
    def as_bytes(dct):
        if '__bytes__' in dct:
            return base64.b64decode(dct['data'])
        return dct

    keys = json.loads(fs_args.get('safefs_keys', '[]'), object_hook=as_bytes)

    if not keys:
        return create_fs

    return EncryptedFSFactory(create_fs, keys)
