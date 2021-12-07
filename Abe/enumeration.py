"""enum-like type"""
# From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
#

from typing import Dict, List, Tuple, Union
from Abe.exceptions import EnumException


class Enumeration:
    """Create a C like enumerated list"""

    def __init__(self, name, enum_list: List[Union[Tuple[str, int], str]]):
        self.__doc__ = name
        lookup: Dict[str, int] = {}
        reverse_lookup: Dict[int, str] = {}
        i: int = 0
        unique_names: List[str] = []
        unique_values: List[int] = []
        for j in enum_list:
            if isinstance(j, tuple):
                j, i = j
            if j in unique_names:
                raise EnumException("enum name is not unique: " + j)
            if i in unique_values:
                raise EnumException("enum value is not unique for " + j)
            unique_names.append(j)
            unique_values.append(i)
            lookup[j] = i
            reverse_lookup[i] = j
            i = i + 1
        self.lookup: Dict[str, int] = lookup
        self.reverse_lookup: Dict[int, str] = reverse_lookup

    def __getattr__(self, attr: str) -> int:
        if not attr in self.lookup:
            raise AttributeError
        return self.lookup[attr]

    def whatis(self, value: int) -> str:
        """Conducts a reverse lookup of the str using the int"""
        return self.reverse_lookup[value]
