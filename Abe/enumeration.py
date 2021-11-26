#
# enum-like type
# From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
#

from .exceptions import EnumException


class Enumeration:
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = {}
        reverse_lookup = {}
        i = 0
        unique_names = []
        unique_values = []
        for j in enumList:
            if isinstance(j, tuple):
                j, i = j
            if not isinstance(j, str):
                raise EnumException("enum name is not a string: " + j)
            if not isinstance(i, int):
                raise EnumException("enum value is not an integer: " + i)
            if j in unique_names:
                raise EnumException("enum name is not unique: " + j)
            if i in unique_values:
                raise EnumException("enum value is not unique for " + j)
            unique_names.append(j)
            unique_values.append(i)
            lookup[j] = i
            reverse_lookup[i] = j
            i = i + 1
        self.lookup = lookup
        self.reverse_lookup = reverse_lookup

    def __getattr__(self, attr):
        if not attr in self.lookup:
            raise AttributeError
        return self.lookup[attr]

    def whatis(self, value):
        return self.reverse_lookup[value]
