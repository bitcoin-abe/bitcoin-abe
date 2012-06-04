# Copyright(C) 2012 by John Tobey <John.Tobey@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

"""
Given a forest of rooted trees, find whether a given node is an
ancestor of another.  Scale to millions of generations: O(N*log(N))
space and O(log(N)) time.
"""

def root():
    """Create and return a new root node."""
    return [0]

def beget(parent):
    """
    Create and return a new child of parent.  Parent must have been
    returned by root() or this method previously.
    """
    pheight = parent[0]
    height = pheight + 1
    bit = 1
    size = len(parent)
    while pheight & bit:
        bit <<= 1
        size -= 1
    return [height] + parent[1:size] + [parent]

def descends_from(node, ancestor):
    """
    Return true if node is descended from ancestor; that is, if node
    is the result of a sequence of zero or more applications of beget
    to ancestor.
    """
    aheight = ancestor[0]
    while True:
        nheight = node[0]
        if nheight <= aheight:
            return node is ancestor
        pos = len(node)
        xor = nheight ^ aheight
        bit = 1
        while xor:
            if nheight & bit:
                pos -= 1
            xor >>= 1
            bit <<= 1
        node = node[pos]
