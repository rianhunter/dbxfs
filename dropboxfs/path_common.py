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

import itertools

def file_name_norm(s):
    return s.lower()

# NB: this acts like a pathlib PurePath object
class Path(object):
    def __init__(self, comps):
        comps = tuple(comps)
        assert all(type(comp) is str for comp in comps)
        self._comps = comps

    @classmethod
    def root_path(cls):
        return cls([])

    @classmethod
    def parse_path(cls, p):
        root = cls.root_path()
        if p == "/":
            return root
        return root.joinpath(*p[1:].split("/"))

    def joinpath(self, *comps):
        return self.__class__(itertools.chain(self._comps, comps))

    @property
    def parts(self):
        return tuple(itertools.chain(('/',), self._comps))

    # NB: This is probably an evil abuse of the '/' operator
    def __truediv__(self, elt):
        return self.joinpath(elt)

    def __repr__(self):
        return 'Path' + str(self)

    def _norm(self):
        return tuple(map(file_name_norm, self._comps))

    def __eq__(self, other):
        return self._norm() == other._norm()

    def __hash__(self):
        return hash(self._norm())

    def __str__(self):
        return '/' + '/'.join(self._comps)

    @property
    def name(self):
        if not self._comps: return ''
        return self._comps[-1]

    @property
    def parent(self):
        if not self._comps: return self
        return Path(self._comps[:-1])

    def normed(self):
        return Path(self._norm())
