# Copyright(C) 2014 by Abe developers.

# test_btc200.py: test Abe loading through Bitcoin Block 200.

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
def btc200(testdb):
    dirname = os.path.join(os.path.split(__file__)[0], 'btc200')
    store = testdb.load('--datadir', dirname)
    return store

def test_block_number(btc200):
    assert btc200.get_block_number(1) == 200

@pytest.fixture(scope="module")
def coinbase_200(btc200):
    return btc200.export_tx(tx_hash = '2b1f06c2401d3b49a33c3f5ad5864c0bc70044c4068f9174546f3cfc1887d5ba')

def test_coinbase_hash(coinbase_200):
    assert coinbase_200['hash'] == '2b1f06c2401d3b49a33c3f5ad5864c0bc70044c4068f9174546f3cfc1887d5ba'

def test_coinbase_in(coinbase_200):
    assert len(coinbase_200['in']) == 1
    assert coinbase_200['vin_sz'] == 1

def test_coinbase_lock_time(coinbase_200):
    assert coinbase_200['lock_time'] == 0

def test_coinbase_prev_out(coinbase_200):
    assert coinbase_200['in'][0]['prev_out'] == {
        "hash": "0000000000000000000000000000000000000000000000000000000000000000", 
        "n": 4294967295
        }

def test_coinbase_raw_scriptSig(coinbase_200):
    assert coinbase_200['in'][0]['raw_scriptSig'] == "04ffff001d0138"

def test_coinbase_out(coinbase_200):
    assert len(coinbase_200['out']) == 1
    assert coinbase_200['vout_sz'] == 1

def test_coinbase_raw_scriptPubKey(coinbase_200):
    assert coinbase_200['out'][0]['raw_scriptPubKey'] == \
        "41045e071dedd1ed03721c6e9bba28fc276795421a378637fb41090192bb9f208630dcbac5862a3baeb9df3ca6e4e256b7fd2404824c20198ca1b004ee2197866433ac"

def test_coinbase_value(coinbase_200):
    assert coinbase_200['out'][0]['value'] == "50.00000000"

def test_coinbase_size(coinbase_200):
    assert coinbase_200['size'] == 134

def test_coinbase_ver(coinbase_200):
    assert coinbase_200['ver'] == 1

@pytest.fixture(scope="module")
def b182t1(btc200):
    return btc200.export_tx(
        tx_hash = '591e91f809d716912ca1d4a9295e70c3e78bab077683f79350f101da64588073',
        format = 'browser')

def test_tx_hash(b182t1):
    assert b182t1['hash'] == '591e91f809d716912ca1d4a9295e70c3e78bab077683f79350f101da64588073'

def test_tx_version(b182t1):
    assert b182t1['version'] == 1

def test_tx_lockTime(b182t1):
    assert b182t1['lockTime'] == 0

def test_tx_size(b182t1):
    assert b182t1['size'] == 275

def test_tx_cc(b182t1):
    assert len(b182t1['chain_candidates']) == 1

def test_tx_chain_name(b182t1):
    assert b182t1['chain_candidates'][0]['chain'].name == 'Bitcoin'

def test_tx_in_longest(b182t1):
    assert b182t1['chain_candidates'][0]['in_longest']

def test_tx_block_nTime(b182t1):
    assert b182t1['chain_candidates'][0]['block_nTime'] == 1231740736

def test_tx_block_height(b182t1):
    assert b182t1['chain_candidates'][0]['block_height'] == 182

def test_tx_block_hash(b182t1):
    assert b182t1['chain_candidates'][0]['block_hash'] == \
        '0000000054487811fc4ff7a95be738aa5ad9320c394c482b27c0da28b227ad5d'

def test_tx_tx_pos(b182t1):
    assert b182t1['chain_candidates'][0]['tx_pos'] == 1

def test_tx_in(b182t1):
    assert len(b182t1['in']) == 1

def test_tx_in_pos(b182t1):
    assert b182t1['in'][0]['pos'] == 0

def test_tx_in_binscript(b182t1):
    assert b182t1['in'][0]['binscript'] == '47304402201f27e51caeb9a0988a1e50799ff0af94a3902403c3ad4068b063e7b4d1b0a76702206713f69bd344058b0dee55a9798759092d0916dbbc3e592fee43060005ddc17401'.decode('hex')

def test_tx_in_value(b182t1):
    assert b182t1['in'][0]['value'] == 3000000000

def test_tx_in_prev_out(b182t1):
    assert b182t1['in'][0]['o_hash'] == 'a16f3ce4dd5deb92d98ef5cf8afeaf0775ebca408f708b2146c4fb42b41e14be'
    assert b182t1['in'][0]['o_pos'] == 1

def test_tx_in_script_type(b182t1):
    assert b182t1['in'][0]['script_type'] == Abe.Chain.SCRIPT_TYPE_PUBKEY

def test_tx_in_binaddr(b182t1):
    assert b182t1['in'][0]['binaddr'] == '11b366edfc0a8b66feebae5c2e25a7b6a5d1cf31'.decode('hex')

def test_tx_out(b182t1):
    assert len(b182t1['out']) == 2

def test_tx_out_pos(b182t1):
    assert b182t1['out'][0]['pos'] == 0
    assert b182t1['out'][1]['pos'] == 1

def test_tx_out_binscript(b182t1):
    assert b182t1['out'][0]['binscript'] == '410401518fa1d1e1e3e162852d68d9be1c0abad5e3d6297ec95f1f91b909dc1afe616d6876f92918451ca387c4387609ae1a895007096195a824baf9c38ea98c09c3ac'.decode('hex')
    assert b182t1['out'][1]['binscript'] == '410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac'.decode('hex')

def test_tx_out_value(b182t1):
    assert b182t1['out'][0]['value'] == 100000000
    assert b182t1['out'][1]['value'] == 2900000000

def test_tx_out_redeemed(b182t1):
    assert b182t1['out'][0]['o_hash'] is None
    assert b182t1['out'][0]['o_pos'] is None
    assert b182t1['out'][1]['o_hash'] == '12b5633bad1f9c167d523ad1aa1947b2732a865bf5414eab2f9e5ae5d5c191ba'
    assert b182t1['out'][1]['o_pos'] == 0

def test_tx_out_binaddr(b182t1):
    assert b182t1['out'][0]['binaddr'] == 'db3b465a2b678e0bdc3e4944bb41abb5a795ae04'.decode('hex')
    assert b182t1['out'][1]['binaddr'] == '11b366edfc0a8b66feebae5c2e25a7b6a5d1cf31'.decode('hex')

def test_tx_value_in(b182t1):
    assert b182t1['value_in'] == 3000000000

def test_tx_value_out(b182t1):
    assert b182t1['value_out'] == 3000000000
