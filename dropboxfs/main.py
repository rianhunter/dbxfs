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
import sys

import appdirs

import dropbox

import userspacefs

from dropboxfs.dbfs import FileSystem as DropboxFileSystem
from dropboxfs.memory_cache_fs import FileSystem as CachingFileSystem
from dropboxfs.disable_quick_look import FileSystem as DisableQuickLookFileSystem

log = logging.getLogger(__name__)

def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser()
    userspacefs.add_cli_arguments(parser)
    parser.add_argument("-c", "--config-file")
    args = parser.parse_args(argv[1:])

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

    return userspacefs.simple_main("dropboxfs", create_fs, args)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
