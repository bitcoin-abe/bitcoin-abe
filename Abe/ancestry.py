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

10100011011101  10461
10100011011100  10460
10100011011011  10459
10100011010111  10455
10100011001111  10447
10100010111111  10431
10100001111111  10367
10011111111111  10239
01111111111111   8191

+-------+---+    +---+---+       +---+---+       +---+---+
| 10461 | o----->| o | o------+->| o | o-------+>| o | o---->...
+-------+---+    +-|-+---+   /   +-|-+---+     | +-|-+---+
                   |        /      |           |   |
                   V       /       V           |   V
                 +-------+-|-+   +-------+---+ | +-------+---+
                 | 10460 | o |   | 10459 | o | | | 10455 | o |
                 +-------+---+   +-------+-|-+ | +-------+---+
                                    /-----/     \
                                   V             \--\
                                 +---+---+    +---+-|-+
                                 | o | o----->| o | o |
                                 +-|-+---+  ^ +-|-+---+
                                   V        |   V
                              +-------+---+ / +-------+---+
                              | 10458 | o--/  | 10457 | o |
                              +-------+---+   +-------+---+

1111111111111   8191
1111111111110   8190
1111111111101   8189
1111111111011   8187
1111111110111   8183
1111111101111   8175
1111111011111   8159
1111110111111   8127
1111101111111   8063
1111011111111   7935
1110111111111   7679
1101111111111   7167
1011111111111   6143
0111111111111   4095
"""

def root():
    """Create and return a new root node."""
    return (0, None)

def beget(parent):
    """
    Create and return a new child of parent.  Parent must have been
    returned by root() or this method previously.
    """
    pheight, index = parent
    bit = 1
    while pheight & bit:
        bit <<= 1
        index = index[1]
    return (pheight + 1, (parent, index))

def generation(node):
    """
    Return node's generation number, 0 for roots and 1 plus parent's
    generation for child nodes.
    """
    return node[0]

def descend(node, count):
    """
    Return the result of count applications of beget to node.
    """
    # This could be optimized by lazily creating nodes in ascend().
    while count > 0:
        node = beget(node)
    return node

def ascend(node, count):
    """
    Return node's ancestor count generations past.
    """
    nheight, above = node
    if count < 0 or count > nheight:
        raise IndexError("count out of range %d, %d" % (count, nheight))
    if count < 1:
        return node

    height = nheight - count
    while True:
        assert above[0][0] >= height
        below = above[1]
        if below is None:
            below = above[0][1]
        if below and below[0][0] >= height:
            above = below
            continue

        anode = above[0]
        aheight = anode[0]
        if aheight == height:
            return anode

        middle = above[0][1]
        if middle and middle[0][0] >= height:
            above = middle
            continue

        raise Exception("want to insert a node", node, count)

def descends_from(node, ancestor):
    """
    Return true if node is descended from ancestor; that is, if node
    is the result of a series of zero or more applications of beget to
    ancestor.
    """
    count = node[0] - ancestor[0]
    return count >= 0 and ancestor is ascend(node, count)
