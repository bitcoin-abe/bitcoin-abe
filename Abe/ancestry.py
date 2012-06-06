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
ancestor of another.  Scale to millions of generations: O(N) space and
O(log(N)) time.

    +---+-+-+
    | 0 | | |
    +---+-+-+
      ^
       \--\
          |
    +---+-|-+-+
    | 1 | * | |
    +---+---+-+
      ^
       \-----\
          \   \
    +---+-|-+-|-+
    | 2 | * | * |
    +---+---+---+
      ^
       \--\
          |
    +---+-|-+-+
    | 3 | * | |
    +---+---+-+
      ^
       \----------\
          \   \    \
    +---+-|-+-|-+  |
    | 4 | * | * |  |
    +---+---+---+  |
      ^            |
       \--\        |
          |        |
    +---+-|-+---+  |
    | 5 | * | *----/
    +---+---+---+

Every node has a generation number (0=root) and two pointer slots.
The first slot heads a linked list that includes every node back to
the root, sorted by decreasing generation number.  The second slot
heads a similarly sorted, linked list containing a subset of the
ancestor nodes, chosen to speed searches.

All this assumes that descendant nodes are created one generation at a
time.  If descend_to is called with a generation number greater than
its argument's by more than 1, the linked lists will be incomplete.
When we create intervening nodes, we modify the lists in place.

"""

def root():
    """Create and return a new root node."""
    return [0, None, None]

def generation(node):
    """
    Return node's generation number: 0 for a root, or 1 plus the
    parent's generation number.
    """
    return node[0]

def _next_express(n):
    bit = 1
    while bit & n:
        bit <<= 1
    return n - bit

def descend_to(node, number):
    """
    Return a new child with the given generation number, descended
    from node through generations of new nodes.  If number is less
    than node's generation, return ascend_to(node, number) instead.

    As an optimization, for number > 1 + generation(node), this does
    not immediately create the intervening nodes; ascend_to creates
    them on demand.
    """
    if number <= node[0]:
        return ascend_to(node, number)
    desired = _next_express(number)
    express = node
    while express and express[0] > desired:
        express = express[2]
    return [number, node, express]

def beget(parent):
    """
    Return a new, immediate child of parent; shorthand for
    descend_to(parent, generation(parent) + 1).
    """
    return descend_to(parent, 1 + parent[0])

def _ascend(node, number):
    # Return node's earliest *allocated* ancestor with generation not
    # less than number.
    while node[0] > number:
        if node[2] and node[2][0] >= number:
            node = node[2]
        elif node[1][0] >= number:
            node = node[1]
        else:
            return node
    assert node[0] == number
    return node

def ascend_to(node, number):
    """
    Return node's ancestor that has the given generation number.
    """
    if number > node[0]:
        raise IndexError("generation number too high, %d > %d"
                         % (number, node[0]))
    if number < 0:
        raise IndexError("negative generation number: %d" % number)

    ancestor = _ascend(node, number)

    if ancestor[0] == number:
        return ancestor

    ret = descend_to(ancestor[1], number)
    ancestor[1] = ret
    if number <= _next_express(ancestor[0]):
        ancestor[2] = ret

    return ret

def descends_from(node, ancestor):
    """
    Return true if node is descended from ancestor.  Consider every
    node descended from itself.
    """
    return ancestor[0] <= node[0] and ancestor is _ascend(node, ancestor[0])

def defragment(node):
    # Optimize node's ancestors, assuming they were allocated non-sequentially.
    # XXX
    raise Exception("defragment is not implemented")
