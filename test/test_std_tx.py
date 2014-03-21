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

import db, datagen
from Abe.deserialize import opcodes

@pytest.fixture(scope="module")
def chain():
    store = db.create().new_store()
    chain = store.get_chain_by_name('Testnet')
    gen = datagen.Gen(chain = chain)

    pubkey_0 = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'.decode('hex')
    pubkey_1 = '021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51'.decode('hex')

    block_0_hash = '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943'.decode('hex')[::-1]
    block_1_hash = '00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206'.decode('hex')[::-1]

    genesis_coinbase = gen.coinbase(
        scriptSig=gen.encode_script(
            '\xff\xff\x00\x1d', '\x04', 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'),
        txOut=[gen.txout(pubkey=pubkey_0, value=50*10**8)])

    blocks = [ gen.block(transactions=[genesis_coinbase], nTime=1296688602, nNonce=414098458) ]
    assert blocks[0]['hash'] == block_0_hash

    blocks.append( gen.block(prev=blocks[-1], nTime=1296688928, nNonce=1924588547,
                             transactions=[gen.coinbase(scriptSig='0420e7494d017f062f503253482f'.decode('hex'),
                                                        txOut=[gen.txout(pubkey=pubkey_1, value=50*10**8)])]) )
    assert blocks[1]['hash'] == block_1_hash

    for i in xrange(12):
        blocks.append( gen.block(prev=blocks[-1]) )

    blocks.append( gen.block(prev=blocks[-1],
                             transactions=[gen.coinbase(),
                                           gen.tx(txIn=[gen.txin(prevout=blocks[1]['transactions'][0]['txOut'][0],
                                                                 scriptSig='XXX')],
                                                  txOut=[gen.txout(addr='n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ',
                                                                   value=999000000),
                                                         gen.txout(addr='2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb',
                                                                   value=2000000000),
                                                         gen.txout(multisig={"m":2, "pubkeys":[
                                    '0269184483e5494727d2dec54da85db9b18bee827bb3d1eee23b122edf810b8262'.decode('hex'),
                                    '0217819b778f0bcfee53bbed495ca20fdc828f40ffd6d9481fe4c0d091b1486f69'.decode('hex'),
                                    '022820a6eb4e6817bf68301856e0803e05d19f54714006f2088e74103be396eb5a'.decode('hex'),
                                    ]},
                                                                   value=2000000000)])]) )

    for block in blocks:
        store.import_block(block, chain = chain)
    store.commit()

    tx = store.export_tx(tx_hash=blocks[-1]['transactions'][1]['hash'][::-1].encode('hex'), format='browser')
    assert tx['out'][0]['binaddr'] == 'deb1f1ffbef6061a0b8f6d23b4e72164b4678253'.decode('hex')

    return store

def test_test(chain):
    pass
