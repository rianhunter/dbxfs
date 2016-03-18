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
import errno
import json
import logging
import os
import random
import signal
import subprocess
import sys
import threading

import dropbox

from dropboxfs.smbserver import SMBServer
from dropboxfs.dbfs import FileSystem as DropboxFileSystem
from dropboxfs.memory_cache_fs import FileSystem as CachingFileSystem
from dropboxfs.disable_quick_look import FileSystem as DisableQuickLookFileSystem

log = logging.getLogger(__name__)

def main(argv=None):
    if argv is None:
        argv = sys.argv

    def ensure_port(string):
        port = int(string)
        if not (0 < port < 65536):
            raise argparse.ArgumentTypeError("%r is not a valid TCP port" % (string,))
        return port

    parser = argparse.ArgumentParser()
    parser.add_argument("mount_point", nargs=1)
    args = parser.parse_args(argv[1:])

    (mount_point,) = args.mount_point

    logging.basicConfig(level=logging.DEBUG)

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

    # NB: Binding to this port could fail
    # TODO: keep randomly binding until we find a port
    port = random.randint(60000, 2 ** 16)

    address = ('127.0.0.1', port)
    server = SMBServer(address, DisableQuickLookFileSystem(CachingFileSystem(DropboxFileSystem(access_token))))

    do_unmount = False

    def run_server():
        try:
            server.run()
        except:
            _thread.interrupt_main()
            raise

    threading.Thread(target=run_server, daemon=True).start()

    if sys.platform != "darwin":
        log.warn("Couldn't mount file system automatically, not on Mac OS X")
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
