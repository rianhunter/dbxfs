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

from block_tracing import block_tracing

from dbxfs.dbfs import FileSystem as DropboxFileSystem
from dbxfs.memory_cache_fs import FileSystem as CachingFileSystem
from dbxfs.disable_quick_look import FileSystem as DisableQuickLookFileSystem
from dbxfs.safefs_glue import safefs_wrap_create_fs

log = logging.getLogger(__name__)

def yes_no_input(message=None):
    answer = input("%s[y/N]" % (message + ' ' if message is not None else ''))
    while answer.lower().strip() not in ("y", "n", "yes", "no", ""):
        print("Please answer yes or no!")
        answer = input("%s[y/N]" % (message + ' ' if message is not None else ''))
    return answer.lower().startswith('y')

def main(argv=None):
    # Protect access token and potentially encryption keys
    block_tracing()

    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser()
    userspacefs.add_cli_arguments(parser)
    parser.add_argument("-c", "--config-file")
    parser.add_argument("-e", "--encrypted-folder", dest='encrypted_folders', action='append')
    args = parser.parse_args(argv[1:])

    if args.config_file is not None:
        config_file = args.config_file
    else:
        config_file = os.path.expanduser("~/.dbxfs")

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

    while True:
        if access_token is None:
            print("First go to https://dropbox.com/developers/apps to "
                  "create an app then generate an access token for yourself! (Press Ctrl-C if you make a mistake)")
            access_token = input("Enter Access Token: ")

            print("We're all connected. Do you want to save this access token to disk? Caution: it can be saved and abused by a rogue program to access your entire Dropbox!")
            if yes_no_input():
                with open(config_file, "w") as f:
                    json.dump(dict(access_token=access_token), f)

        # test out access token
        try:
            dropbox.Dropbox(access_token).users_get_current_account()
        except (dropbox.exceptions.BadInputError,
                dropbox.exceptions.AuthError) as e:
            print("Error using access token: %s" % (e.message,))
            answer = yes_no_input("Create new access token?")
            if not answer:
                print("Okay, quitting!")
                return 0
            else:
                access_token = None
                os.remove(config_file)
        else:
            break

    cache_folder = os.path.join(appdirs.user_cache_dir(), "dbxfs", "file_cache")
    with contextlib.suppress(FileExistsError):
        os.makedirs(cache_folder)

    def create_fs():
        fs = CachingFileSystem(DropboxFileSystem(access_token), cache_folder=cache_folder)
        if sys.platform == 'darwin':
            fs = DisableQuickLookFileSystem(fs)
        return fs

    create_fs = safefs_wrap_create_fs(create_fs, args.encrypted_folders)

    return userspacefs.simple_main("dbxfs", create_fs, args)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
