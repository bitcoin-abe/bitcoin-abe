# Copyright(C) 2014 by Abe developers.

# test_std_tx.py: test Abe importing standard Bitcoin transaction types.

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

    # Test block with an interesting transaction.
    blocks.append(
        gen.block(
            prev=blocks[-1],
            transactions=[
                gen.coinbase(value=50.01e8),
                gen.tx(txIn=[gen.txin(prevout=blocks[1]['transactions'][0]['txOut'][0], scriptSig='XXX')],
                       txOut=[gen.txout(addr='n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ', value=9.99e8),
                              gen.txout(addr='2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb', value=20e8),
                              gen.txout(multisig={"m":2, "pubkeys":data.PUBKEYS[2:5]}, value=20e8)])]) )

    if 'ABE_TEST_SAVE_BLKFILE' in os.environ:
        gen.save_blkfile(os.environ['ABE_TEST_SAVE_BLKFILE'], blocks)

    # XXX Lots of code duplicated in test_block_order.py.
    datadir = py.path.local(tempfile.mkdtemp(prefix='abe-test-'))
    request.addfinalizer(datadir.remove)
    gen.save_blkfile(str(datadir.join('blk0001.dat')), blocks)

    gen.store = testdb.load('--datadir', json.dumps([{
                    'dirname': str(datadir),
                    'chain': chain.name,
                    'loader': 'blkfile'}]))
    gen.chain = gen.store.get_chain_by_name(chain.name)

    return gen

def test_b0_hash(gen):
    # Testnet Block 0 hash.
    block_0_hash = '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943'.decode('hex')[::-1]
    assert gen.blocks[0]['hash'] == block_0_hash

def test_b1_hash(gen):
    # Testnet Block 1 hash.
    block_1_hash = '00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206'.decode('hex')[::-1]
    assert gen.blocks[1]['hash'] == block_1_hash

@pytest.fixture(scope="module")
def ahn1p(gen):
    return data.ah(gen, 'n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ')

def test_ahn1p_binaddr(ahn1p):
    assert ahn1p['binaddr'] == 'deb1f1ffbef6061a0b8f6d23b4e72164b4678253'.decode('hex')

def test_ahn1p_subbinaddr(ahn1p):
    assert 'subbinaddr' not in ahn1p

def test_ahn1p_version(ahn1p):
    assert ahn1p['version'] == '\x6f'

def test_ahn1p_chains(ahn1p):
    assert len(ahn1p['chains']) == 1

def test_ahn1p_c0_name(ahn1p):
    assert ahn1p['chains'][0].name == 'Testnet'

def test_ahn1p_balance(ahn1p, gen):
    assert ahn1p['balance'] == { gen.chain.id: 9.99e8 }

def test_ahn1p_txpoints(ahn1p):
    assert len(ahn1p['txpoints']) == 1

def test_ahn1p_p0_type(ahn1p):
    assert ahn1p['txpoints'][0]['type'] == 'direct'

def test_ahn1p_p0_is_out(ahn1p):
    assert not ahn1p['txpoints'][0]['is_out']

def test_ahn1p_p0_nTime(ahn1p):
    assert ahn1p['txpoints'][0]['nTime'] == 1231006506

def test_ahn1p_p0_chain(ahn1p):
    assert ahn1p['txpoints'][0]['chain'].name == 'Testnet'

def test_ahn1p_p0_height(ahn1p):
    assert ahn1p['txpoints'][0]['height'] == 14

def test_ahn1p_p0_blk_hash(ahn1p):
    assert ahn1p['txpoints'][0]['blk_hash'] == '0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e'

def test_ahn1p_p0_tx_hash(ahn1p):
    assert ahn1p['txpoints'][0]['tx_hash'] == 'dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52'

def test_ahn1p_p0_pos(ahn1p):
    assert ahn1p['txpoints'][0]['pos'] == 0

def test_ahn1p_p0_value(ahn1p):
    assert ahn1p['txpoints'][0]['value'] == 9.99e8

def test_ahn1p_sent(ahn1p, gen):
    assert ahn1p['sent'] == { gen.chain.id: 0 }

def test_ahn1p_received(ahn1p, gen):
    assert ahn1p['received'] == { gen.chain.id: 9.99e8 }

def test_ahn1p_counts(ahn1p):
    assert ahn1p['counts'] == [1, 0]

@pytest.fixture(scope="module")
def a2NFT(gen):
    return data.ah(gen, '2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb')

def test_a2NFT_binaddr(a2NFT):
    assert a2NFT['binaddr'] == 'f3aae15f9b92a094bb4e01afe99f99ab4135f362'.decode('hex')

def test_a2NFT_subbinaddr(a2NFT):
    assert 'subbinaddr' not in a2NFT

def test_a2NFT_version(a2NFT):
    assert a2NFT['version'] == '\xc4'

def test_a2NFT_chains(a2NFT):
    assert len(a2NFT['chains']) == 1

def test_a2NFT_c0_name(a2NFT):
    assert a2NFT['chains'][0].name == 'Testnet'

def test_a2NFT_balance(a2NFT, gen):
    assert a2NFT['balance'] == { gen.chain.id: 20e8 }

def test_a2NFT_txpoints(a2NFT):
    assert len(a2NFT['txpoints']) == 1

def test_a2NFT_p0_type(a2NFT):
    assert a2NFT['txpoints'][0]['type'] == 'direct'

def test_a2NFT_p0_is_out(a2NFT):
    assert not a2NFT['txpoints'][0]['is_out']

def test_a2NFT_p0_nTime(a2NFT):
    assert a2NFT['txpoints'][0]['nTime'] == 1231006506

def test_a2NFT_p0_chain(a2NFT):
    assert a2NFT['txpoints'][0]['chain'].name == 'Testnet'

def test_a2NFT_p0_height(a2NFT):
    assert a2NFT['txpoints'][0]['height'] == 14

def test_a2NFT_p0_blk_hash(a2NFT):
    assert a2NFT['txpoints'][0]['blk_hash'] == '0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e'

def test_a2NFT_p0_tx_hash(a2NFT):
    assert a2NFT['txpoints'][0]['tx_hash'] == 'dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52'

def test_a2NFT_p0_pos(a2NFT):
    assert a2NFT['txpoints'][0]['pos'] == 1

def test_a2NFT_p0_value(a2NFT):
    assert a2NFT['txpoints'][0]['value'] == 20e8

def test_a2NFT_sent(a2NFT, gen):
    assert a2NFT['sent'] == { gen.chain.id: 0 }

def test_a2NFT_received(a2NFT, gen):
    assert a2NFT['received'] == { gen.chain.id: 20e8 }

def test_a2NFT_counts(a2NFT):
    assert a2NFT['counts'] == [1, 0]

@pytest.fixture(scope="module")
def an3j4(gen):
    return data.ah(gen, 'n3j41Rkn51bdfh3NgyaA7x2JKEsfuvq888')

def test_an3j4_binaddr(an3j4, gen):
    assert an3j4['binaddr'] == gen.chain.pubkey_hash(data.PUBKEYS[3])

def test_an3j4_subbinaddr(an3j4, gen):
    assert 'subbinaddr' not in an3j4

def test_an3j4_version(an3j4):
    assert an3j4['version'] == '\x6f'

def test_an3j4_chains(an3j4):
    assert len(an3j4['chains']) == 1

def test_an3j4_c0_name(an3j4):
    assert an3j4['chains'][0].name == 'Testnet'

def test_an3j4_balance(an3j4, gen):
    assert an3j4['balance'] == { gen.chain.id: 0 }

def test_an3j4_txpoints(an3j4):
    assert len(an3j4['txpoints']) == 1

def test_an3j4_p0_type(an3j4):
    assert an3j4['txpoints'][0]['type'] == 'escrow'

def test_an3j4_p0_is_out(an3j4):
    assert not an3j4['txpoints'][0]['is_out']

def test_an3j4_p0_nTime(an3j4):
    assert an3j4['txpoints'][0]['nTime'] == 1231006506

def test_an3j4_p0_chain(an3j4):
    assert an3j4['txpoints'][0]['chain'].name == 'Testnet'

def test_an3j4_p0_height(an3j4):
    assert an3j4['txpoints'][0]['height'] == 14

def test_an3j4_p0_blk_hash(an3j4):
    assert an3j4['txpoints'][0]['blk_hash'] == '0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e'

def test_an3j4_p0_tx_hash(an3j4):
    assert an3j4['txpoints'][0]['tx_hash'] == 'dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52'

def test_an3j4_p0_pos(an3j4):
    assert an3j4['txpoints'][0]['pos'] == 2

def test_an3j4_p0_value(an3j4):
    assert an3j4['txpoints'][0]['value'] == 20e8

def test_an3j4_sent(an3j4, gen):
    assert an3j4['sent'] == { gen.chain.id: 0 }

def test_an3j4_received(an3j4, gen):
    assert an3j4['received'] == { gen.chain.id: 0 }

def test_an3j4_counts(an3j4):
    assert an3j4['counts'] == [0, 0]

# TODO: look up multisig by its P2SH address, check subbinaddr.
# TODO: test different types of redeemed outputs.

def b(gen, b):
    return gen.store.export_block(chain=gen.chain, block_number=b)

@pytest.fixture(scope="module")
def b14(gen):
    return b(gen, 14)

def test_b14_chain_candidates(b14):
    assert len(b14['chain_candidates']) == 1

def test_b14cc0_chain_name(b14):
    assert b14['chain_candidates'][0]['chain'].name == 'Testnet'

def test_b14cc0_in_longest(b14):
    assert b14['chain_candidates'][0]['in_longest']

def test_b14_chain_satoshis(b14):
    assert b14['chain_satoshis'] == 750*10**8

def test_b14_chain_satoshi_seconds(b14):
    assert b14['chain_satoshi_seconds'] == -656822590000000000

def test_b14_chain_work(b14):
    assert b14['chain_work'] == 64425492495

def test_b14_fees(b14):
    assert b14['fees'] == 0.01e8

def test_b14_generated(b14):
    assert b14['generated'] == 50e8

def test_b14_hash(b14):
    assert b14['hash'] == '0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e'

def test_b14_hashMerkleRoot(b14):
    assert b14['hashMerkleRoot'] == '93f17b59330df6c97f8d305572b0b98608b34a2f4fa235e6ff69bbe343e3a764'

def test_b14_hashPrev(b14):
    assert b14['hashPrev'] == '2155786533653694385a772e33d9547848c809b1d1bce3500a377fe37ad3d250'

def test_b14_height(b14):
    assert b14['height'] == 14

def test_b14_nBits(b14):
    assert b14['nBits'] == 0x1d00ffff

def test_b14_next_block_hashes(b14):
    assert b14['next_block_hashes'] == []

def test_b14_nNonce(b14):
    assert b14['nNonce'] == 253

def test_b14_nTime(b14):
    assert b14['nTime'] == 1231006506

@pytest.mark.xfail
def test_b14_satoshis_destroyed(b14):
    # XXX Is this value right?
    assert b14['satoshis_destroyed'] == -328412110000000000

@pytest.mark.xfail
def test_b14_satoshi_seconds(b14):
    # XXX Is this value right?
    assert b14['satoshi_seconds'] == -328410480000000000

def test_b14_transactions(b14):
    assert len(b14['transactions']) == 2

def test_b14_t1_fees(b14):
    assert b14['transactions'][1]['fees'] == 0.01e8

def test_b14_t1_hash(b14):
    assert b14['transactions'][1]['hash'] == 'dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52'

def test_b14_t1_in(b14):
    assert len(b14['transactions'][1]['in']) == 1

def test_b14_t1i0_address_version(b14):
    assert b14['transactions'][1]['in'][0]['address_version'] == '\x6f'

def test_b14_t1i0_binaddr(b14, gen):
    assert b14['transactions'][1]['in'][0]['binaddr'] == gen.chain.pubkey_hash(data.PUBKEYS[1])

def test_b14_t1i0_value(b14):
    assert b14['transactions'][1]['in'][0]['value'] == 50e8

def test_b14_t1_out(b14):
    assert len(b14['transactions'][1]['out']) == 3

def test_b14_t1o0_address_version(b14):
    assert b14['transactions'][1]['out'][0]['address_version'] == '\x6f'

def test_b14_t1o0_binaddr(b14, gen):
    assert b14['transactions'][1]['out'][0]['binaddr'] == 'deb1f1ffbef6061a0b8f6d23b4e72164b4678253'.decode('hex')

def test_b14_t1o0_value(b14):
    assert b14['transactions'][1]['out'][0]['value'] == 9.99e8

def test_b14_t1o1_address_version(b14):
    assert b14['transactions'][1]['out'][1]['address_version'] == '\xc4'

def test_b14_t1o1_binaddr(b14, gen):
    assert b14['transactions'][1]['out'][1]['binaddr'] == 'f3aae15f9b92a094bb4e01afe99f99ab4135f362'.decode('hex')

def test_b14_t1o1_value(b14):
    assert b14['transactions'][1]['out'][1]['value'] == 20e8

def test_b14_t1o2_address_version(b14):
    assert b14['transactions'][1]['out'][2]['address_version'] == '\x6f'

def test_b14_t1o2_binaddr(b14, gen):
    assert b14['transactions'][1]['out'][2]['binaddr'] == 'b8bcada90d0992bdc64188d6a0ac3f9fd200d1d1'.decode('hex')

def test_b14_t1o2_subbinaddr(b14, gen):
    assert len(b14['transactions'][1]['out'][2]['subbinaddr']) == 3

def test_b14_t1o2k0(b14, gen):
    assert b14['transactions'][1]['out'][2]['subbinaddr'][0] == gen.chain.pubkey_hash(data.PUBKEYS[2])

def test_b14_t1o2k1(b14, gen):
    assert b14['transactions'][1]['out'][2]['subbinaddr'][1] == gen.chain.pubkey_hash(data.PUBKEYS[3])

def test_b14_t1o2k2(b14, gen):
    assert b14['transactions'][1]['out'][2]['subbinaddr'][2] == gen.chain.pubkey_hash(data.PUBKEYS[4])

def test_b14_t1o2_required_signatures(b14):
    assert b14['transactions'][1]['out'][2]['required_signatures'] == 2

def test_b14_t1o2_value(b14):
    assert b14['transactions'][1]['out'][2]['value'] == 20e8

def test_b14_value_out(b14):
    assert b14['value_out'] == 100e8

def test_b14_version(b14):
    assert b14['version'] == 1

def bt(gen, b, t):
    return gen.store.export_tx(tx_hash=gen.blocks[b]['transactions'][t]['hash'][::-1].encode('hex'), format='browser')

@pytest.fixture(scope="module")
def b14t1(gen):
    return bt(gen, 14, 1)

def test_b14t1o0_script_type(b14t1):
    assert b14t1['out'][0]['script_type'] == Abe.Chain.SCRIPT_TYPE_ADDRESS

def test_b14t1o0_binaddr(b14t1):
    assert b14t1['out'][0]['binaddr'] == Abe.util.decode_address('n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ')[1]
    assert b14t1['out'][0]['binaddr'] == 'deb1f1ffbef6061a0b8f6d23b4e72164b4678253'.decode('hex')

def test_b14t1o0_value(b14t1):
    assert b14t1['out'][0]['value'] == 9.99e8

def test_b14t1o1_script_type(b14t1):
    assert b14t1['out'][1]['script_type'] == Abe.Chain.SCRIPT_TYPE_P2SH

def test_b14t1o1_binaddr(b14t1):
    assert b14t1['out'][1]['binaddr'] == Abe.util.decode_address('2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb')[1]

def test_b14t1o1_value(b14t1):
    assert b14t1['out'][1]['value'] == 20e8

def test_b14t1o2_script_type(b14t1):
    assert b14t1['out'][2]['script_type'] == Abe.Chain.SCRIPT_TYPE_MULTISIG

def test_b14t1o2_required_signatures(b14t1):
    assert b14t1['out'][2]['required_signatures'] == 2

def test_b14t1o2_binaddr(b14t1, gen):
    assert b14t1['out'][2]['binaddr'] == 'b8bcada90d0992bdc64188d6a0ac3f9fd200d1d1'.decode('hex')

def test_b14t1o2_subbinaddr(b14t1, gen):
    assert b14t1['out'][2]['subbinaddr'] == [ gen.chain.pubkey_hash(pubkey) for pubkey in data.PUBKEYS[2:5] ]

def test_b14t1o2_value(b14t1):
    assert b14t1['out'][2]['value'] == 20e8
