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

import argparse
import contextlib
import errno
import json
import logging
import os
import queue
import random
import socket
import signal
import subprocess
import sys
import syslog
import threading

import appdirs

import dropbox

try:
    from dropboxfs.fuse_adapter import run_fuse_mount
except EnvironmentError:
    run_fuse_mount = None

from dropboxfs.smbserver import SMBServer
from dropboxfs.dbfs import FileSystem as DropboxFileSystem
from dropboxfs.memory_cache_fs import FileSystem as CachingFileSystem
from dropboxfs.disable_quick_look import FileSystem as DisableQuickLookFileSystem

log = logging.getLogger(__name__)

def daemonize():
    res = os.fork()
    if res:
        return res

    os.setsid()

    os.chdir("/")

    nullfd = os.open("/dev/null", os.O_RDWR)
    try:
        os.dup2(nullfd, 0)
        os.dup2(nullfd, 1)
        os.dup2(nullfd, 2)
    finally:
        os.close(nullfd)

class RealSysLogHandler(logging.Handler):
    def __init__(self, *n, **kw):
        super().__init__()
        syslog.openlog(*n, **kw)

    def _map_priority(self, levelname):
        return {
            logging.DEBUG:    syslog.LOG_DEBUG,
            logging.INFO:     syslog.LOG_INFO,
            logging.ERROR:    syslog.LOG_ERR,
            logging.WARNING:  syslog.LOG_WARNING,
            logging.CRITICAL: syslog.LOG_CRIT,
            }[levelname]

    def emit(self, record):
        msg = self.format(record)
        priority = self._map_priority(record.levelno)
        syslog.syslog(priority, msg)

class SimpleSMBBackend(object):
    def __init__(self, path, fs):
        self._path = path
        self._fs = fs

    def tree_connect(self, server, path):
        if path.rsplit("\\", 1)[-1].upper() == self._path.rsplit("\\", 1)[-1].upper():
            return self._fs
        raise KeyError()

    def tree_disconnect(self, server, fs):
        pass

    def tree_disconnect_hard(self, server, fs):
        pass

def main(argv=None):
    if argv is None:
        argv = sys.argv

    def ensure_listen_address(string):
        try:
            (host, port) = string.split(":", 1)
        except ValueError:
            try:
                port = int(string)
                if not (0 < port < 65536):
                    raise ValueError()
            except ValueError:
                host = string
                port = None
            else:
                host = ''
        else:
            if port:
                port = int(port)
                if not (0 < port < 65536):
                    raise argparse.ArgumentTypeError("%r is not a valid TCP port" % (port,))
            else:
                port = None

        if not host:
            host = "127.0.0.1"

        return (host, port)

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--foreground", action="store_true")
    parser.add_argument("-c", "--config-file")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-s", "--smb-only", action="store_true")
    parser.add_argument("-n", "--smb-no-mount", action="store_true")
    parser.add_argument("-l", "--smb-listen-address", default="127.0.0.1", type=ensure_listen_address)
    parser.add_argument("mount_point", nargs=1)
    args = parser.parse_args(argv[1:])

    (mount_point,) = args.mount_point
    mount_point = os.path.abspath(mount_point)

    if args.foreground:
        format_ = '%(asctime)s:%(levelname)s:%(name)s:%(message)s'
        logging_stream = logging.StreamHandler()
    else:
        format_ = '%(levelname)s:%(name)s:%(message)s'
        logging_stream = RealSysLogHandler("dropboxfs", syslog.LOG_PID)

    level = [logging.WARNING, logging.INFO, logging.DEBUG][min(2, args.verbose)]
    logging.basicConfig(level=level, handlers=[logging_stream], format=format_)

    if args.config_file is not None:
        config_file = args.config_file
    else:
        config_file = os.path.expanduser("~/.dropboxfs")

    access_token = None
    try:
        f = open(config_file)
    except IOError as e:
        if e.errno != errno.ENOENT: raise
    else:
        try:
            with f:
                access_token = json.load(f).get("access_token", None)
            if type(access_token) != str:
                access_token = None
                raise ValueError("access token isn't a str")
        except (ValueError, AttributeError):
            os.remove(config_file)

    if access_token is None:
        print("First go to https://dropbox.com/developers/apps to "
              "create an app and get an API key and secret! (Press Ctrl-C if you make a mistake)")
        app_key = input("Enter App Key: ")
        app_secret = input("Enter App Secret: ")
        auth_flow = dropbox.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
        authorize_url = auth_flow.start()
        print("1. Go to: " + authorize_url)
        print("2. Click \"Allow\" (you might have to log in first).")
        print("3. Copy the authorization code.")
        auth_code = input("Enter the authorization code here: ").strip()

        access_token, _ = auth_flow.finish(auth_code)

        print("We're all connected. Do you want to save this access token to disk? Caution: it can be saved and abused by a rogue program to access your entire Dropbox!")
        answer = input("[y/N]: ")
        while answer.strip() not in ("y", "n", "yes", "no", ""):
            print("Please answer yes or no!")
            answer = input("[y/N]: ")
        if answer in ("y", "yes"):
            with open(config_file, "w") as f:
                json.dump(dict(access_token=access_token), f)

    cache_folder = os.path.join(appdirs.user_cache_dir(), "dropboxfs", "file_cache")
    with contextlib.suppress(FileExistsError):
        os.makedirs(cache_folder)

    def create_fs():
        fs = CachingFileSystem(DropboxFileSystem(access_token), cache_folder=cache_folder)
        if sys.platform == 'darwin':
            fs = DisableQuickLookFileSystem(fs)
        return fs

    if not args.smb_only and run_fuse_mount is not None:
        log.debug("Attempting fuse mount")
        run_fuse_mount(create_fs, mount_point, foreground=args.foreground)
        return 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    (host, port) = args.smb_listen_address

    if port is None:
        while True:
            port = random.randint(60000, 2 ** 16)
            try:
                sock.bind((host, port))
            except OSError as err:
                if err.errno != errno.EADDRINUSE: raise
            else:
                break
    else:
        for prop in ('SO_REUSEADDR', 'SO_REUSEPORT'):
            if hasattr(socket, prop):
                sock.setsockopt(socket.SOL_SOCKET, getattr(socket, prop), True)

        sock.bind((host, port))

    can_mount_smb_automatically = sys.platform == "darwin" and not args.smb_no_mount
    if not can_mount_smb_automatically:
        print("%s, you can access the SMB server at cifs://guest:@%s:%d/dropboxfs" %
              ("Not mounting file system automatically"
               if args.smb_no_mount else
               "Can't mount file system automatically",
               host,
               port,))

    def mount_notify(child_pid):
        if can_mount_smb_automatically:
            ret = subprocess.call(["mount", "-t", "smbfs",
                                   "cifs://guest:@127.0.0.1:%d/dropboxfs" % (port,),
                                   mount_point])
            if ret:
                os.kill(child_pid, signal.SIGTERM)
            else:
                os.kill(child_pid, signal.SIGUSR1)
        else:
            ret = 0
        return ret

    if not args.foreground:
        child_pid = daemonize()

        if child_pid:
            return mount_notify(child_pid)
    else:
        threading.Thread(target=mount_notify, args=(os.getpid(),), daemon=True).start()

    server = SMBServer(SimpleSMBBackend("\\\\127.0.0.1\\dropboxfs", create_fs()),
                       sock=sock)

    mm_q = queue.Queue()
    def check_mount():
        is_mounted = False
        while True:
            try:
                r = mm_q.get(timeout=(None
                                      if not is_mounted else
                                      1 if args.foreground else 30))
            except queue.Empty:
                pass
            else:
                if r:
                    is_mounted = True
                else:
                    break

            if is_mounted and not os.path.ismount(mount_point):
                is_mounted = False
                break

        if is_mounted:
            subprocess.call(["umount", "-f", mount_point])

        server.close()
    threading.Thread(target=check_mount, daemon=True).start()

    def handle_mounted(self, *_):
        mm_q.put(True)

    def kill_signal(self, *_):
        mm_q.put(False)

    signal.signal(signal.SIGTERM, kill_signal)
    signal.signal(signal.SIGINT, kill_signal)
    signal.signal(signal.SIGUSR1, handle_mounted)

    server.run()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
