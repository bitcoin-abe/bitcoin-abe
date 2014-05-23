# Copyright(C) 2014 by Abe developers.

# test_max200.py: test Abe loading through Maxcoin Block 200.
# This test exercises SHA3 block hashes and an unusual Merkle root algorithm.

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

import pytest

from db import testdb
import os
import Abe.util
import Abe.Chain

@pytest.fixture(scope="module")
def max200(testdb):
    try:
        Abe.util.sha3_256('x')
    except Exception as e:
        pytest.skip('SHA3 not working: e')
    dirname = os.path.join(os.path.split(__file__)[0], 'max200')
    store = testdb.load('--datadir', dirname)
    return store

def test_block_number(max200):
    assert max200.get_block_number(max200.get_chain_by_name('Maxcoin').id) == 200
