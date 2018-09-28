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
import getpass
import json
import logging
import os
import subprocess
import sys

import appdirs

import dropbox

import privy

import userspacefs

from block_tracing import block_tracing

from dbxfs.dbxfs import FileSystem as DropboxFileSystem
from dbxfs.memory_cache_fs import FileSystem as CachingFileSystem
from dbxfs.disable_quick_look import FileSystem as DisableQuickLookFileSystem

try:
    from dbxfs.safefs_glue import safefs_wrap_create_fs
except ImportError:
    def safefs_wrap_create_fs(create_fs, ef):
        if ef:
            log.warn("safefs not installed, can't transparently decrypt encrypted folders")
        return create_fs

log = logging.getLogger(__name__)

APP_NAME = "dbxfs"

def yes_no_input(message=None):
    answer = input("%s[y/N]" % (message + ' ' if message is not None else ''))
    while answer.lower().strip() not in ("y", "n", "yes", "no", ""):
        print("Please answer yes or no!")
        answer = input("%s[y/N]" % (message + ' ' if message is not None else ''))
    return answer.lower().startswith('y')

def parse_encrypted_folder_arg(string):
    return dict(path=string)

def main(argv=None):
    # Protect access token and potentially encryption keys
    block_tracing()

    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser()
    userspacefs.add_cli_arguments(parser)
    parser.add_argument("-c", "--config-file")
    parser.add_argument("-e", "--encrypted-folder", dest='encrypted_folders', type=parse_encrypted_folder_arg, default=[], action='append')
    args = parser.parse_args(argv[1:])

    config_dir = appdirs.user_config_dir(APP_NAME)

    if args.config_file is not None:
        config_file = args.config_file
    else:
        config_file = os.path.join(config_dir, "config.json")

    config = {}
    try:
        f = open(config_file)
    except IOError as e:
        if e.errno != errno.ENOENT: raise
    else:
        try:
            with f:
                config = json.load(f)
        except ValueError as e:
            print("Config file %r is not valid json: %r" % (config_file, e.message))
            return -1

    access_token = None

    access_token_command = config.get("access_token_command", None)
    if access_token_command is not None:
        print("Running %r for access token" % (' '.join(access_token_command),))
        try:
            access_token = subprocess.check_output(access_token_command).decode("utf-8")
        except TypeError:
            print("Bad access token command: %r, " % (access_token_command,))
            return -1

    if access_token is None:
        access_token_privy = config.get("access_token_privy", None)
        if access_token_privy is not None:
            passwd = None
            while True:
                passwd = getpass.getpass("Enter access token passphrase (not your Dropbox password): ")
                try:
                    access_token = privy.peek(access_token_privy, passwd).decode('utf-8')
                except ValueError:
                    if not yes_no_input("Incorrect password, create new access token?"):
                        continue
                break
            del passwd

    save_access_token = False
    while True:
        if access_token is None:
            print("We need an access token. "
                  "Go to https://dropbox.com/developers/apps to "
                  "create an app and generate a personal access token.")

            access_token = getpass.getpass("Enter Access token: ")
            if not access_token:
                print("Access tokens cannot be empty")
                access_token = None
                continue
            save_access_token = True

        # test out access token
        try:
            dropbox.Dropbox(access_token).users_get_current_account()
        except (dropbox.exceptions.BadInputError,
                dropbox.exceptions.AuthError) as e:
            print("Error using access token: %s" % (e.message,))
            access_token = None
        else:
            break

    if save_access_token and yes_no_input("We're all connected. Do you want to save this access token for future runs?"):
        print("We need a passphrase to encrypt your access token before we can save it.")
        print("Warning: Your access token passphrase must contain enough randomness to be resistent to hacking. You can read this for more info: https://blogs.dropbox.com/tech/2012/04/zxcvbn-realistic-password-strength-estimation/")
        while True:
            pass_ = getpass.getpass("Enter new access token passphrase: ")
            pass2_ = getpass.getpass("Enter new access token passphrase (again): ")
            if pass_ != pass2_:
                print("Passphrases didn't match, please re-enter")
            else:
                del pass2_
                break
        config['access_token_privy'] = privy.hide(access_token.encode('utf-8'), pass_, server=False)
        del pass_
        with open(config_file, "w") as f:
            json.dump(config, f)

    print("Successfully authenticated, starting %r..." % (APP_NAME,))

    cache_folder = os.path.join(appdirs.user_cache_dir(APP_NAME), "file_cache")
    with contextlib.suppress(FileExistsError):
        os.makedirs(cache_folder)

    def create_fs():
        fs = CachingFileSystem(DropboxFileSystem(access_token), cache_folder=cache_folder)
        if sys.platform == 'darwin':
            fs = DisableQuickLookFileSystem(fs)
        return fs

    encrypted_folders = config.get("encrypted_folders", []) + args.encrypted_folders

    create_fs = safefs_wrap_create_fs(create_fs, encrypted_folders)

    return userspacefs.simple_main("dbxfs", create_fs, args)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
