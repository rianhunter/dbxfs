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
import random
import signal
import subprocess
import sys
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
        sys.exit(0)
        raise Exception("should never get here")

    os.setsid()

    os.chdir("/")

    nullfd = os.open("/dev/null", os.O_RDWR)
    try:
        os.dup2(nullfd, 0)
        os.dup2(nullfd, 1)
        os.dup2(nullfd, 2)
    finally:
        os.close(nullfd)

def main(argv=None):
    if argv is None:
        argv = sys.argv

    def ensure_port(string):
        port = int(string)
        if not (0 < port < 65536):
            raise argparse.ArgumentTypeError("%r is not a valid TCP port" % (string,))
        return port

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--foreground", action="store_true")
    parser.add_argument("-c", "--config-file")
    parser.add_argument("-p", "--port", type=ensure_port)
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-s", "--smb-only", action="store_true")
    parser.add_argument("mount_point", nargs=1)
    args = parser.parse_args(argv[1:])

    (mount_point,) = args.mount_point

    level = [logging.WARNING, logging.INFO, logging.DEBUG][min(2, args.verbose)]
    logging.basicConfig(level=level)

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

    if args.port is None:
        # NB: Binding to this port could fail
        # TODO: keep randomly binding until we find a port
        port = random.randint(60000, 2 ** 16)
    else:
        port = args.port

    cache_folder = os.path.join(appdirs.user_cache_dir(), "dropboxfs", "file_cache")
    with contextlib.suppress(FileExistsError):
        os.makedirs(cache_folder)

    address = ('127.0.0.1', port)
    fs = CachingFileSystem(DropboxFileSystem(access_token), cache_folder=cache_folder)
    if sys.platform == 'darwin':
        fs = DisableQuickLookFileSystem(fs)

    if not args.smb_only and run_fuse_mount is not None:
        log.debug("Attempting fuse mount")
        run_fuse_mount(fs, mount_point, foreground=args.foreground)
        return 0

    server = SMBServer(address, fs)

    do_unmount = False

    def run_server():
        try:
            server.run()
        except:
            _thread.interrupt_main()
            raise

    can_mount_smb_automatically = sys.platform == "darwin"
    if not can_mount_smb_automatically:
        print("Can't mount file system automatically, you can access the SMB server at cifs://guest:@127.0.0.01:%d/dropboxfs" % (port,))

    if not args.foreground:
        daemonize()

    threading.Thread(target=run_server, daemon=True).start()

    if not can_mount_smb_automatically:
        signal.pause()
    else:
        subprocess.check_call(["mount", "-t", "smbfs",
                               "cifs://guest:@127.0.0.1:%d/dropboxfs" % (port,),
                               mount_point])

        try:
            signal.pause()
        finally:
            subprocess.call(["umount", "-f", mount_point])

if __name__ == "__main__":
    sys.exit(main(sys.argv))
