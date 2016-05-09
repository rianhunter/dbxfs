# don't abuse this file!

# for the 99.9% of you for which the preceding comment is unclear:

# keep this file small, if there is a theme of utility functions then
# put group them into a separate file

import contextlib
import io
import datetime
import threading

def utctimestamp(dt):
    assert dt.tzinfo is None
    return dt.replace(tzinfo=datetime.timezone.utc).timestamp()

class PositionIO(io.RawIOBase):
    def __init__(self):
        self._offset_lock = threading.Lock()
        self._offset = 0

    def readinto(self, ibuf):
        with self._offset_lock:
            obuf = self.pread(len(ibuf), self._offset)
            ibuf[:len(obuf)] = obuf
            self._offset += len(obuf)
            return len(obuf)

    def write(self, buf):
        with self._offset_lock:
            ret = self.pwrite(buf, self._offset)
            self._offset += ret
            return ret

    def seek(self, amt, whence=0):
        with self._offset_lock:
            if whence == io.SEEK_SET:
                self._offset = amt
            elif whence == io.SEEK_CUR:
                self._offset += amt
            elif whence == io.SEEK_END:
                self._offset = self._file_length() + amt
            else:
                raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))

    def truncate(self):
        with self._offset_lock:
            return self.ptruncate(self._offset)

    def seekable(self):
        return hasattr(self, '_file_length')

@contextlib.contextmanager
def null_context():
    yield

class quick_container(object):
    def __init__(self, **kw):
        self._fields = []
        for (k, v) in kw.items():
            setattr(self, k, v)
            self._fields.append(k)
        self._fields = tuple(self._fields)

    def __repr__(self):
        return 'quick_container(' + ','.join("%s=%r" % (k, getattr(self, k)) for k in self._fields) + ')'
