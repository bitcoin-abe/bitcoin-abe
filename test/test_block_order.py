# Copyright(C) 2014 by Abe developers.

# test_block_order.py: test Abe importing blocks out of order.

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

import os
import json
import tempfile
import py.path

from db import testdb
import data
import Abe.Chain
from Abe.deserialize import opcodes

@pytest.fixture(scope="module")
def gen(testdb, request):
    gen = data.testnet14(testdb)
    chain = gen.chain
    blocks = gen.blocks

    # A - C* - D**
    #   \
    #     E  - B*
    #
    # * contains tx1
    # ** contains tx2

    tx1 = gen.tx(txIn=[gen.txin(prevout=blocks[1]['transactions'][0]['txOut'][0], scriptSig='XXX')],
                 txOut=[gen.txout(addr='n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ', value=50e8)])
    A = blocks[-1]
    C = gen.block(prev=A, transactions=[gen.coinbase(), tx1])
    E = gen.block(prev=A)
    B = gen.block(prev=E, transactions=[gen.coinbase(), tx1])

    tx2 = gen.tx(txIn=[gen.txin(prevout=C['transactions'][1]['txOut'][0], scriptSig='YYY')],
                 txOut=[gen.txout(addr='2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb', value=50e8)])

    D = gen.block(prev=C, transactions=[gen.coinbase(), tx2])

    blocks += [B, C, D, E]

    # XXX Lots of code duplicated in test_std_tx.py.
    datadir = py.path.local(tempfile.mkdtemp(prefix='abe-test-'))
    request.addfinalizer(datadir.remove)
    gen.save_blkfile(str(datadir.join('blk0001.dat')), blocks)

    gen.store = testdb.load('--datadir', json.dumps([{
                    'dirname': str(datadir),
                    'chain': chain.name,
                    'loader': 'blkfile'}]))
    gen.chain = gen.store.get_chain_by_name(chain.name)

    return gen

@pytest.fixture(scope="module")
def a2NFT(gen):
    return data.ah(gen, '2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb')

def test_a2NFT_balance(a2NFT, gen):
    assert a2NFT['balance'] == { gen.chain.id: 50e8 }
