dbxfs
=====

dbxfs allows you to mount your Dropbox folder as if it were a local
filesystem. It differs from the official Dropbox client in two main
ways:

* Internet connectivity is required for access
* No disk space is required for access, but will cache if disk space is available

dbxfs has been tested on OpenBSD, Linux, and macOS but it should run on any
POSIX system that provides a FUSE-compatible library or has the
ability to mount SMB shares. Windows support is coming very soon. It
runs on non-x86 architectures like ARM. It doesn't require a specific
file system.

It is written for Python 3.5+ and is licensed under the GPLv3.

Disclaimer: dbxfs is not affiliated with Dropbox, Inc.

Installation
------------

If you are on Linux, you must install your OS's FUSE library. On
Debian/Ubuntu, install the ``libfuse2`` package, on Fedora install
``fuse``.

Run the following command::

  $ pip3 install dbxfs

On Arch Linux and derivatives, you can find it in the AUR as
`dbxfs <https://aur.archlinux.org/packages/dbxfs>`_.

Usage
-----

Use ``dbxfs`` like you would use the ``mount`` command::

  $ dbxfs <mount_point>

To unmount your Dropbox folder on Linux systems, you can use
``fusermount -u <mount_point>``, on all other systems use ``umount``.

You can see the full list of command line options by passing ``-h`` to
the ``dbxfs`` command.

Advanced Access Token Storage
-----------------------------

By default dbxfs stores your access token in the system keyring or an
encrypted file but you may want to store it in a GPG encrypted file
or something else. To do that you must first obtain an access token.
You can obtain an access token by creating a personal app on the
`Dropbox developers app console <https://dropbox.com/developers/apps>`_.

Once you have obtained an app token, encrypt it with the program of
your choice and store the result somewhere. After that, you must edit
the dbxfs config file. You can find the location of the config file by
running the following command::

  $ dbxfs --print-default-config-file

The config file is a JSON encoded file. Add the following JSON key to
the top-level JSON object in that file::

  "access_token_command": ["gpg", "--decrypt", "/path/to/access/token/file.gpg"]

Adapt it to a decryption program of your choice. This configuration
works great for storing the access token using a OpenPGP card.

Contact
-------

Rian Hunter `@cejetvole <https://twitter.com/cejetvole>`_
