import datagen
import Abe.Chain
from Abe.util import hex2b

PUBKEYS = [
    x.decode('hex') for x in [
        # Satoshi's genesis pubkey.
        '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f',

        # Testnet Block 1 pubkey.
        '021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51',

        # Some test pubkeys.
        '0269184483e5494727d2dec54da85db9b18bee827bb3d1eee23b122edf810b8262',
        '0217819b778f0bcfee53bbed495ca20fdc828f40ffd6d9481fe4c0d091b1486f69',
        '022820a6eb4e6817bf68301856e0803e05d19f54714006f2088e74103be396eb5a',
        ]]

def testnet14(db):
    chain = Abe.Chain.create('Testnet')
    blocks = []
    gen = datagen.Gen(chain=chain, db=db, blocks=blocks)

    # The Bitcoin/Testnet genesis transaction.
    genesis_coinbase = gen.coinbase(
        scriptSig=gen.encode_script(
            '\xff\xff\x00\x1d', '\x04', 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'),
        txOut=[gen.txout(pubkey=PUBKEYS[0], value=50*10**8)])

    # Testnet Blocks 0 and 1.
    blocks.append(gen.block(transactions=[genesis_coinbase], nTime=1296688602, nNonce=414098458))

    blocks.append( gen.block(prev=blocks[-1], nTime=1296688928, nNonce=1924588547,
                             transactions=[gen.coinbase(scriptSig=hex2b('0420e7494d017f062f503253482f'),
                                                        txOut=[gen.txout(pubkey=PUBKEYS[1], value=50*10**8)])]) )

    # Test blocks with random coinbase addresses and bogus proof-of-work.
    for i in xrange(12):
        blocks.append( gen.block(prev=blocks[-1]) )

    return gen

def ah(gen, addr):
    return gen.store.export_address_history(addr, chain=gen.chain)
