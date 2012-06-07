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

Every node has a generation number (0=root) and two pointer slots.
The first slot heads a linked list that includes every node back to
the root, sorted by decreasing generation number.  The second slot
heads a similarly sorted, linked list containing a subset of the
ancestor nodes, chosen to speed searches.
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
    assert n >= 1
    bit = 1
    while (bit & n) == 0:
        bit <<= 1
    return n - bit

def descend_to(node, number):
    """
    Return a new child with the given generation number, descended
    from node through generations of new nodes.  If number is less
    than node's generation, return ascend_to(node, number) instead.

    As an optimization, for number > 1 + generation(node), this may
    not create all intervening nodes.  ascend_to creates them on
    demand, in which case thread safety is an issue.
    """
    assert number == int(number)

    if number <= node[0]:
        return ascend_to(node, number)

    desired = _next_express(number)
    express = node
    while express[0] > desired:
        express = express[2]
    if express[0] < desired:
        express = descend_to(express, desired)

    local = node
    if express[0] > local[0]:
        local = express

    return [number, local, express]

def beget(parent):
    """
    Return a new, immediate child of parent; shorthand for
    descend_to(parent, generation(parent) + 1).
    """
    return descend_to(parent, 1 + parent[0])

def _ascend(node, number):
    # Return node's earliest *allocated* ancestor with generation not
    # less than number.
    assert node[0] >= number
    while node[0] > number:
        if node[2][0] >= number:
            node = node[2]
        elif node[1][0] >= number:
            node = node[1]
        else:
            return node
    return node

def ascend_to(node, number):
    """
    Return node's ancestor that has the given generation number.
    """
    assert number == int(number)
    if number > node[0]:
        raise IndexError("generation number too high, %d > %d"
                         % (number, node[0]))
    if number < 0:
        raise IndexError("negative generation number: %d" % number)

    ancestor = _ascend(node, number)

    if ancestor[0] == number:
        return ancestor

    # Thread-unsafety here.
    ret = descend_to(ancestor[1], number)
    ancestor[1] = ret

    return ret

def descends_from(node, ancestor):
    """
    Return true if node is descended from ancestor or node is ancestor.
    """
    return ancestor[0] <= node[0] and ancestor is _ascend(node, ancestor[0])
