# Copyright(C) 2014 by Abe developers.

"""test_block_order.py: test Abe importing blocks out of order."""

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

import os
import json
import tempfile
import pytest
from . import data
from .db import testdb  # pylint: disable=unused-import


# pylint: disable=redefined-outer-name, invalid-name
@pytest.fixture(scope="module")
def gen(testdb, request):
    """Initialize reproducible testing data for the module"""
    _gen = data.testnet14(testdb)
    chain = _gen.chain
    blocks = _gen.blocks

    # A - C* - D**
    #   \
    #     E  - B*
    #
    # * contains tx1
    # ** contains tx2

    tx1 = _gen.tx(
        txIn=[
            _gen.txin(prevout=blocks[1]["transactions"][0]["txOut"][0], scriptSig="XXX")
        ],
        txOut=[_gen.txout(addr="n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ", value=int(50e8))],
    )
    block_a = blocks[-1]
    block_c = _gen.block(prev=block_a, transactions=[_gen.coinbase(), tx1])
    block_e = _gen.block(prev=block_a)
    block_b = _gen.block(prev=block_e, transactions=[_gen.coinbase(), tx1])

    tx2 = _gen.tx(
        txIn=[
            _gen.txin(prevout=block_c["transactions"][1]["txOut"][0], scriptSig="YYY")
        ],
        txOut=[_gen.txout(addr="2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb", value=int(50e8))],
    )

    block_d = _gen.block(prev=block_c, transactions=[_gen.coinbase(), tx2])

    blocks += [block_b, block_c, block_d, block_e]

    # XXX Lots of code duplicated in test_std_tx.py.
    datadir = tempfile.mkdtemp(prefix="abe-test-")
    # os.chmod(datadir, stat.S_IRWXU)
    _gen.save_blkfile(datadir + "/blk0001.dat", blocks)

    _gen.store = testdb.load(
        "--datadir",
        json.dumps([{"dirname": datadir, "chain": chain.name, "loader": "blkfile"}]),
    )
    request.addfinalizer(os.rmdir(datadir))
    _gen.chain = _gen.store.get_chain_by_name(chain.name)

    return _gen


@pytest.fixture(scope="module")
def a2NFT(gen):
    """Get a wallet address"""
    return data.address_history(gen, "2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb")


def test_a2NFT_balance(a2NFT, gen):
    """Test the wallet's balance"""
    assert a2NFT["balance"] == {gen.chain.id: int(50e8)}
