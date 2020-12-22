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
import functools
import getpass
import pkg_resources
import io
import json
import logging
import os
import random
import subprocess
import sys
import syslog
import urllib.request

import appdirs

import dropbox

import privy

import userspacefs

import keyring
from keyring.errors import KeyringError

import sentry_sdk

from block_tracing import block_tracing, BLOCK_TRACING_INHERITS

from dbxfs.dbxfs import FileSystem as DropboxFileSystem
from dbxfs.cachingfs import FileSystem as CachingFileSystem, check_runtime_requirements
from dbxfs.disable_quick_look import FileSystem as DisableQuickLookFileSystem
from dbxfs.translate_ignored_files import FileSystem as TranslateIgnoredFilesFileSystem

try:
    from dbxfs.safefs_glue import safefs_wrap_create_fs, safefs_add_fs_args
except ImportError:
    safefs_wrap_create_fs = None
    safefs_add_fs_args = None

log = logging.getLogger(__name__)

APP_NAME = "dbxfs"

# This exposure is intentional
APP_KEY = "iftkeq2y4qj0nbt"
APP_SECRET = "y245xn4rg4lf0it"

def yes_no_input(message=None, default_yes=False):
    if default_yes:
        extra = "[Y/n]"
    else:
        extra = "[y/N]"
    answer = input("%s%s " % (message + ' ' if message is not None else '', extra))
    while answer.lower().strip() not in ("y", "n", "yes", "no", ""):
        print("Please answer yes or no!")
        answer = input("%s%s " % (message + ' ' if message is not None else '', extra))
    if not answer.lower().strip():
        return default_yes
    return answer.lower().startswith('y')

def parse_encrypted_folder_arg(string):
    return dict(path=string)

def base_create_fs(access_token, cache_folder):
    fs = CachingFileSystem(DropboxFileSystem(access_token), cache_folder=cache_folder)

    # From a purity standpoint the following layer ideally would
    # go between the caching fs and dropbox fs, but because the
    # contract between those two is highly specialized, just put
    # it on top
    fs = TranslateIgnoredFilesFileSystem(fs)

    if sys.platform == 'darwin':
        fs = DisableQuickLookFileSystem(fs)

    return fs

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

def on_new_process(proc_args):
    # Protect access token and potentially encryption keys
    if not BLOCK_TRACING_INHERITS:
        block_tracing()

    display_name = proc_args['display_name']
    verbose = int(proc_args['verbose'])

    format_ = '%(levelname)s:%(name)s:%(message)s'
    logging_stream = RealSysLogHandler(display_name, syslog.LOG_PID)

    level = [logging.WARNING, logging.INFO, logging.DEBUG][min(2, verbose)]
    logging.basicConfig(level=level, handlers=[logging_stream], format=format_)

def create_fs(fs_args):
    access_token = fs_args['access_token']
    cache_folder = fs_args['cache_folder']

    sub_create_fs = functools.partial(base_create_fs, access_token, cache_folder)

    if safefs_wrap_create_fs is not None:
        sub_create_fs = safefs_wrap_create_fs(sub_create_fs, fs_args)

    return sub_create_fs()

class FUSEOption(argparse.Action):
    def __init__(self, **kw):
        super(FUSEOption, self).__init__(**kw)

    def __call__(self, parser, ns, values, option_string):
        if ns.o is None:
            ns.o = {}
        for kv in values.split(","):
            ret = kv.split("=", 1)
            if len(ret) == 2:
                ns.o[ret[0]] = ret[1]
            else:
                ns.o[ret[0]] = True

def add_cli_arguments(parser):
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

    parser.add_argument("-f", "--foreground", action="store_true",
                        help="keep filesystem server in foreground")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="show log messages, use twice for maximum verbosity")
    parser.add_argument("-s", "--smb", action="store_true",
                        help="force mounting via SMB")
    parser.add_argument("-n", "--smb-no-mount", action="store_true",
                        help="export filesystem via SMB but don't mount it")
    parser.add_argument("-l", "--smb-listen-address", default="127.0.0.1",
                        type=ensure_listen_address,
                        help="address that SMB service should listen on, append colon to specify port")
    parser.add_argument("-o", metavar='opt,[opt...]', action=FUSEOption,
                        help="FUSE options, e.g. -o uid=1000,allow_other")

def _main(argv=None):
    if sys.version_info < (3, 5):
        print("Error: Your version of Python is too old, 3.5+ is required: %d.%d.%d" % sys.version_info[:3])
        return -1

    try:
        check_runtime_requirements()
    except RuntimeError as e:
        print("Error: %s" % (e,))
        return -1

    # Protect access token and potentially encryption keys
    block_tracing()

    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser()
    add_cli_arguments(parser)
    parser.add_argument("-c", "--config-file",
                        help="config file path")
    parser.add_argument("-e", "--encrypted-folder",
                        dest='encrypted_folders',
                        type=parse_encrypted_folder_arg,
                        default=[], action='append',
                        help="relative paths of encrypted folders, can be used multiple times. requires safefs")
    parser.add_argument("--print-default-config-file", action='store_true',
                        help="print default config file path to standard out and quit")
    parser.add_argument("--cache-dir",
                        help="file cache directory")
    parser.add_argument("mount_point", nargs='?')
    args = parser.parse_args(argv[1:])

    format_ = '%(asctime)s:%(levelname)s:%(name)s:%(message)s'
    logging_stream = logging.StreamHandler()

    level = [logging.WARNING, logging.INFO, logging.DEBUG][min(2, args.verbose)]
    logging.basicConfig(level=level, handlers=[logging_stream], format=format_)

    try:
        version = pkg_resources.require("dbxfs")[0].version
    except Exception:
        log.warning("Failed to get version", exc_info=True)
        version = ''

    if version:
        try:
            with urllib.request.urlopen("https://pypi.org/pypi/dbxfs/json") as f:
                rversion = json.load(io.TextIOWrapper(f))['info']['version']
                if rversion != version:
                    print("\033[0;31m\033[1mWarning: dbxfs is out of date (%s vs %s), upgrade with 'pip3 install --upgrade dbxfs'\033[0;0m" %
                          (rversion, version))
        except Exception:
            log.warning("Failed to get most recent version", exc_info=True)

    config_dir = appdirs.user_config_dir(APP_NAME)

    if args.config_file is not None:
        config_file = args.config_file
    else:
        config_file = os.path.join(config_dir, "config.json")

    if args.print_default_config_file:
        print(config_file)
        return 0

    try:
        os.makedirs(config_dir, exist_ok=True)
    except OSError as e:
        print("Unable to create configuration directory: %s" % (e,))
        return -1

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
            print("Config file %r is not valid json: %s" % (config_file, e))
            return -1

    cache_folder = args.cache_dir
    if cache_folder is None:
        cache_folder = config.get("cache_dir")

    mount_point = args.mount_point
    if mount_point is None:
        mount_point = config.get("mount_point")

    if not args.smb_no_mount and mount_point is None:
        parser.print_usage()
        print("%s: error: please provide the mount_point argument" % (os.path.basename(argv[0]),))
        return 1

    encrypted_folders = config.get("encrypted_folders", []) + args.encrypted_folders

    access_token = None
    save_access_token = False
    save_config = False

    access_token_command = config.get("access_token_command", None)
    if access_token_command is not None:
        print("Running %r for access token" % (' '.join(access_token_command),))
        try:
            access_token = subprocess.check_output(access_token_command).decode("utf-8")
        except UnicodeDecodeError:
            print("Access token command output is not utf-8 encoded")
            return -1
        except TypeError:
            print("Bad access token command: %r, " % (access_token_command,))
            return -1
        # NB: access tokens never contain white-space and the access token
        #     command often accidentally appends a newline character.
        access_token = access_token.strip()

    if access_token is None:
        keyring_user = config.get("keyring_user", None)

        if keyring_user is not None:
            try:
                access_token = keyring.get_password(APP_NAME, keyring_user)
            except KeyringError as e:
                print("Failed to get access token from keyring: %s" % (e,))

    if access_token is None:
        access_token_privy = config.get("access_token_privy", None)
        if access_token_privy is not None:
            passwd = None
            while True:
                passwd = getpass.getpass("Enter access token passphrase (not your Dropbox password) (Ctrl-C to quit): ")
                try:
                    access_token = privy.peek(access_token_privy, passwd).decode('utf-8')
                except ValueError:
                    if not yes_no_input("Incorrect password, create new access token?"):
                        continue
                break
            del passwd

    try_directly = False
    while True:
        if access_token is None:
            save_access_token = True

        if (access_token is None and
            try_directly and
            yes_no_input("Want to try entering the access token directly?")):
            print("Go to https://dropbox.com/developers/apps to "
                  "create an app and generate a personal access token.")

            while True:
                access_token = getpass.getpass("Enter Access token (Ctrl-C to quit): ")
                if not access_token:
                    print("Access tokens cannot be empty")
                    continue
                break

        if access_token is None:
            auth_flow = dropbox.DropboxOAuth2FlowNoRedirect(APP_KEY, APP_SECRET)
            authorize_url = auth_flow.start()
            print("We need an access token. Perform the following steps:")
            print("1. Go to " + authorize_url)
            print("2. Click \"Allow\" (you may have to log in first)")
            print("3. Copy the authorization code.")

            while True:
                auth_code = input("Enter authorization code (Ctrl-C to quit): ")
                if not auth_code:
                    print("Authorization code cannot be empty")
                    continue
                break

            try:
                oauth_result = auth_flow.finish(auth_code)
            except Exception as e:
                print("Authorization code was invalid!")
                try_directly = True
                continue

            access_token = oauth_result.access_token

        # test out access token
        try:
            dropbox.Dropbox(access_token).users_get_current_account()
        except (dropbox.exceptions.BadInputError,
                dropbox.exceptions.AuthError,
                ValueError) as e:
            print("Error using access token: %s" % (e,))
            access_token = None
            try_directly = True
        except OSError:
            if not yes_no_input("Error connecting to Dropbox, Try again?"):
                return 1
        else:
            break

    if save_access_token and yes_no_input("We're all connected. Do you want to save your credentials for future runs?", default_yes=True):
        keyring_user = ''.join([random.choice("asdfghjklzxcvbnmqwertyuiop")
                                for _ in range(24)])
        try:
            keyring.set_password(APP_NAME, keyring_user, access_token)
        except (KeyringError, RuntimeError) as e:
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
            config.pop('keyring_user', None)
            config['access_token_privy'] = privy.hide(access_token.encode('utf-8'), pass_, server=False)
            del pass_
            save_config = True
        else:
            config.pop('access_token_privy', None)
            config['keyring_user'] = keyring_user
            save_config = True

    if not config.get("asked_send_error_reports", False):
        if yes_no_input("Would you like to help us improve %s by providing anonymous error reports?" % (APP_NAME,), default_yes=True):
            config['send_error_reports'] = True
        config['asked_send_error_reports'] = True
        save_config = True

    if save_access_token and yes_no_input("Do you want \"%s\" to be the default mount point?" % (mount_point,), default_yes=True):
        config['mount_point'] = mount_point
        save_config = True

    if save_config:
        with open(config_file, "w") as f:
            json.dump(config, f)

    log.info("Starting %s...", APP_NAME)

    if config.get('send_error_reports', False):
        try:
            sentry_sdk.init("https://b4b13ebd300849bd92260507a594e618@sentry.io/1293235",
                            release='%s@%s' % (APP_NAME, version),
                            with_locals=False)
        except Exception:
            log.warning("Failed to initialize sentry", exc_info=True)

    if cache_folder is None:
        cache_folder = os.path.join(appdirs.user_cache_dir(APP_NAME), "file_cache")
        try:
            os.makedirs(cache_folder, exist_ok=True)
        except OSError:
            log.warning("Failed to create cache folder, running without file cache")
            cache_folder = None
        log.debug("Using default cache path %s", cache_folder)
    else:
        if not os.path.isdir(cache_folder):
            print("User-provided \"cache_dir\" setting doesn't refer to a directory: \"%s\"" % (cache_folder,))
            return 1
        log.debug("Using custom cache path %s", cache_folder)

    fs_args = {}

    fs_args['access_token'] = access_token
    fs_args['cache_folder'] = cache_folder

    if safefs_add_fs_args is not None:
        with contextlib.closing(base_create_fs(access_token, cache_folder)) as fs:
            safefs_add_fs_args(fs, encrypted_folders, fs_args)
    elif encrypted_folders:
        print("safefs not installed, can't transparently decrypt encrypted folders")
        return 1

    if mount_point is not None and not os.path.exists(mount_point):
        if yes_no_input("Mount point \"%s\" doesn't exist, do you want to create it?" % (mount_point,), default_yes=True):
            try:
                os.makedirs(mount_point, exist_ok=True)
            except OSError as e:
                print("Unable to create mount point: %s" % (e,))
                return -1

    display_name = 'dbxfs'

    proc_args = {}
    proc_args['display_name'] = display_name
    proc_args['verbose'] = str(args.verbose)

    return userspacefs.simple_main(mount_point, display_name,
                                   ('dbxfs.main.create_fs', fs_args),
                                   on_new_process=('dbxfs.main.on_new_process', proc_args),
                                   foreground=args.foreground,
                                   smb_only=args.smb,
                                   smb_no_mount=args.smb_no_mount,
                                   smb_listen_address=args.smb_listen_address,
                                   fuse_options=args.o)

def main(argv=None):
    try:
        return _main(argv)
    except KeyboardInterrupt:
        return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))
