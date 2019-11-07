DropboxFS Design
================

I hope for this to become a fully fledged design document in the
future but since there is no concrete design at the present time it
makes more sense for this document to contain a semi-ordered
collection of ideas. Of course everything here is subject to change.

Goals / Requirements
--------------------

DropboxFS aims to provide on-demand access to data in a user's Dropbox
account. Functionally, it differs from the official Dropbox client in
two major ways:

* Internet connectivity is required for data access.
* No disk space is required for data access.

Like the official Dropbox client, data is still accessible through the
file system of the native operating system.

The File System API
-------------------

As its name implies, DropboxFS is a file system. It works by
implementing a file-system-like interface that is driven by the
operating system.

There is no single cross-platform file-system API and each operating
system / protocol has its own set of quirks. To make DropboxFS
portable across different operating systems, we'll invent our own FS
API and implement DropboxFS in terms of that. Each operating system
will requires a translation layer between its FS API and our internal
one.

Our FS API will build on top of the Python's existing File object API.
We'll also try to be compatible with `pathlib`. Symmetry between our
API and Python's will allow us to easily leverage third-party Python
code (e.g. `shutil.copyfileobj()`). We'll also introduce the idea of a
Directory object:

    class DirectoryEntry(object):
        __slots__ = ['filename']

    class Directory(object):
        def read(self): pass
        def reset(self): pass
        def close(self): pass

A `Directory` object represents a sequence of `DirectoryEntry`
objects.  Each call to the `read()` method returns the next entry in
the sequence.  When there are no more entries left, it returns
`None`. A `DirectoryEntry` object is a collection of metadata such as
filename and optionally size and type.

The File System object will be the main entry point into the file
system:

    class FileSystem(object):
        def open(self, path, mode): pass
        def remove_file(self, path): pass
        def make_directory(self, path): pass
        def open_directory(self, path): pass
        def remove_directory(self, path): pass
        def stat(self, path): pass

The `open()` method returns a Python file-like object that represents
the file at the specified path. The `open_directory()` returns a
`Directory`-like object that represents the directory at the specific
path.  The remove methods makes the object at the specified path
unavailable in future calls to `open()` or `open_directory(). `stat()`
file system metadata for the specified path, such as size or type.

If any operation across the file/directory/file system methods cannot
be completed, an exception is raised.

Architecture
------------

Our FS API is composable and we will use that property to break down
DropboxFS into a number of independent components:

    frontend -> ... -> middleware -> ... -> backend

### Frontend

The "frontend" is the part of DropboxFS that accepts external file
system requests and forwards to the corresponding internal FS API
calls.  It runs the main loop of the application and in effect is
responsible for driving the entire program. On Linux, for example, the
frontend will be the code that integrates with FUSE.

The frontend can also be an implementation of a server protocol, such
as WebDAV or SMB. This is desirable on operating systems that don't
natively provide a user-space file system API such as FUSE.

On Mac OS X the plan is to implement an SMB server on localhost, and
instruct the operating system to mount it as our method of integrating
with the native VFS. The localhost SMB server can also support Windows.

### Backend

The "backend" is an implementation of a file system object that
represents the user's Dropbox. Ideally the backend contains minimal
logic (such as caching policies, etc.) and simply serves as a
straightforward translation layer between our FS API and the Dropbox
servers. We use the Dropbox [Core
API](https://www.dropbox.com/developers/core).

There is potential for complicated logic within the backend pertaining
to TCP/IP connection management. For instance, let's say a user
requests `n` bytes at offset `x` and but the stream for that file is
currently at offset `x - 10`, should the backend wait for the 10 bytes
to arrive or should it terminate the current stream and begin a new
one at offset `x`?

Heuristics here can get arbitrarily complex. I propose we start will
something exceedingly simple and deterministic:

* One file object <-> One HTTP connection
* File `read()` requests always hits the network
* Restart the TCP/IP stream whenever a `read()` request comes at
  a different offset from the current stream position.
* Directory objects cache full directory contents upon `open_directory()`
  (makes use of `/metadata` DB API method)

This will give us a baseline to compare against to help us improve
performance. If this basic design isn't satisfactory, we should
consider either breaking the FS API abstraction for the backend or
make the backend more intelligent.

### Middleware

The middleware component is for any intelligence we'd like to put between
making requests to the server and returning data to the user.

The only planned middleware thus far is a simple LRU cache. That is,
maintain a cache on disk of limited size and cache data as it's requested
by the frontend. When there is no space left for more data, evict the
least recently used data.

I expect that the relationship between the caching middleware and the
backend will evolve as we identify common performance bottlenecks
and/or design issues arise.
