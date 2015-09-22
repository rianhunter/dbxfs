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

import errno
import json
import logging
import os
import sys

import dropbox

from dropboxfs.smbserver import SMBServer
from dropboxfs.dbfs import FileSystem as DropboxFileSystem

def main(argv):
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

        with open(config_file, "w") as f:
            json.dump(dict(access_token=access_token), f)

    address = ('0.0.0.0', 8888)
    server = SMBServer(address, DropboxFileSystem(access_token))

    # TODO: do mount asynchronously

    server.run()

if __name__ == "__main__":
    sys.exit(main(sys.argv))
