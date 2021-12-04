"""Data to be used in the unit tests."""

from typing import Any, Dict, Optional, List
from Abe import Chain
from Abe.deserialize import Block
from Abe.util import hex2b, NULL_HASH
from .datagen import Gen, BlockTest
from .db import DataBasetype

# Block: 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
simple_block: Block = {
    "version": 1,
    "hashPrev": hex2b(
        "000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55"
    )[::-1],
    "hashMerkleRoot": hex2b(
        "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
    )[::-1],
    "nTime": 1231731025,
    "nNonce": 1889418792,
    "nBits": int("0x1d00ffff", 0),
    "transactions": [
        {
            "version": 1,
            "txIn": [
                {
                    "prevout_hash": NULL_HASH,
                    "prevout_n": int("0xffffffff", 0),
                    "scriptSig": hex2b("04ffff001d0102"),
                    "sequence": 4294967295,
                },
            ],
            "txOut": [
                {
                    "value": int(50e8),
                    "scriptPubKey": hex2b(
                        "4104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac"
                    ),
                },
            ],
        },
        {
            "version": 1,
            "txIn": [
                {
                    "prevout_hash": hex2b(
                        "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"
                    )[::-1],
                    "prevout_n": 0,
                    "scriptSig": hex2b(
                        "47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901"
                    ),
                    "sequence": 4294967295,
                },
            ],
            "txOut": [
                {
                    "value": int(10e8),
                    "scriptPubKey": hex2b(
                        "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac"
                    ),
                },
                {
                    "value": int(40e8),
                    "scriptPubKey": hex2b(
                        "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"
                    ),
                },
            ],
        },
    ],
}
simple_block_header_hash = hex2b(
    "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee"
)[::-1]
simple_raw_block = hex2b(
    "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e700201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0102ffffffff0100f2052a01000000434104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac000000000100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
)
simple_block_tx_hashes = [
    hex2b("b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082")[::-1],
    hex2b("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")[::-1],
]
simple_block_raw_tx = [
    hex2b(
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0102ffffffff0100f2052a01000000434104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac00000000"
    ),
    hex2b(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
    ),
]

PUBKEYS: List = [
    # pylint: disable=line-too-long
    hex2b(x)
    for x in [
        # Satoshi's genesis pubkey.
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
        # Testnet Block 1 pubkey.
        "021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51",
        # Some test pubkeys.
        "0269184483e5494727d2dec54da85db9b18bee827bb3d1eee23b122edf810b8262",
        "0217819b778f0bcfee53bbed495ca20fdc828f40ffd6d9481fe4c0d091b1486f69",
        "022820a6eb4e6817bf68301856e0803e05d19f54714006f2088e74103be396eb5a",
    ]
]


def testnet14(data_base: DataBasetype) -> Gen:
    """Testnet test case"""
    chain = Chain.create("Testnet")
    blocks: List[BlockTest] = []
    gen = Gen(chain=chain, data_base=data_base, blocks=blocks)

    # The Bitcoin/Testnet genesis transaction.
    genesis_coinbase = gen.coinbase(
        scriptSig=gen.encode_script(
            b"\xff\xff\x00\x1d",
            b"\x04",
            "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
        ),
        txOut=[gen.txout(pubkey=PUBKEYS[0], value=50 * 10 ** 8)],
    )

    # Testnet Blocks 0 and 1.
    blocks.append(
        gen.block(
            transactions=[genesis_coinbase],
            nTime=1296688602,
            nNonce=414098458,
        )
    )

    blocks.append(
        gen.block(
            prev=blocks[-1],
            nTime=1296688928,
            nNonce=1924588547,
            transactions=[
                gen.coinbase(
                    scriptSig=hex2b("0420e7494d017f062f503253482f"),
                    txOut=[gen.txout(pubkey=PUBKEYS[1], value=50 * 10 ** 8)],
                )
            ],
        )
    )

    # Test blocks with random coinbase addresses and bogus proof-of-work.
    for i in range(12):  # pylint: disable=unused-variable
        blocks.append(gen.block(prev=blocks[-1]))

    return gen


def address_history(gen: Gen, addr: str) -> Optional[Dict[str, Any]]:
    """Generate the address history for a given address"""
    ret = gen.store.export_address_history(addr, chain=gen.chain)
    return ret
