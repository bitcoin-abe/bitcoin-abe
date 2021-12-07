# Copyright(C) 2014 by Abe developers.

"""test_std_tx.py: test Abe importing standard Bitcoin transaction types."""

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
import shutil
import tempfile
from typing import Any, Dict, Optional
from pytest import FixtureRequest, fixture, mark
from Abe.Chain import SCRIPT_TYPE_ADDRESS, SCRIPT_TYPE_P2SH, SCRIPT_TYPE_MULTISIG
from Abe.util import decode_address, hex2b, pubkey_to_hash
from . import data
from .datagen import Gen, DataBasetype
from .db import testdb  # pylint: disable=unused-import

# from Abe.deserialize import opcodes

# pylint: disable=redefined-outer-name invalid-name
@fixture(scope="module")
def gen(testdb: DataBasetype, request: FixtureRequest) -> Gen:
    """Generated Data for the test"""
    _gen = data.testnet14(testdb)
    chain = _gen.chain
    blocks = _gen.blocks

    # Test block with an interesting transaction.
    blocks.append(
        _gen.block(
            prev=blocks[-1],
            transactions=[
                _gen.coinbase(value=50.01e8),
                _gen.tx(
                    txIn=[
                        _gen.txin(
                            prevout_hash=blocks[1]["transactions"][0]["txOut"][0],
                            prevout_n=0,
                            scriptSig="XXX",
                        )
                    ],
                    txOut=[
                        _gen.txout(
                            addr="n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ", value=9.99e8
                        ),
                        _gen.txout(
                            addr="2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb", value=20e8
                        ),
                        _gen.txout(
                            multisig={"m": 2, "pubkeys": data.PUBKEYS[2:5]}, value=20e8
                        ),
                    ],
                ),
            ],
        )
    )

    if "ABE_TEST_SAVE_BLKFILE" in os.environ:
        _gen.save_blkfile(os.environ["ABE_TEST_SAVE_BLKFILE"], blocks)

    datadir = tempfile.mkdtemp(prefix="abe-test-")
    _gen.save_blkfile(datadir + "/blk0001.dat", blocks)

    _gen.store = testdb.load(
        "--datadir",
        json.dumps(
            [{"dirname": str(datadir), "chain": chain.name, "loader": "blkfile"}]
        ),
    )
    request.addfinalizer(shutil.rmtree(datadir))
    _gen.chain = _gen.store.get_chain_by_name(chain.name)

    return _gen


def test_b0_hash(gen) -> None:
    # Testnet Block 0 hash.
    block_0_hash = hex2b(
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    )[::-1]
    assert gen.blocks[0]["hash"] == block_0_hash


def test_b1_hash(gen) -> None:
    # Testnet Block 1 hash.
    block_1_hash = hex2b(
        "00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206"
    )[::-1]
    assert gen.blocks[1]["hash"] == block_1_hash


@fixture(scope="module")
def ahn1p(gen) -> Optional[Dict[str, Any]]:
    return data.address_history(gen, "n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ")


def test_ahn1p_binaddr(ahn1p) -> None:
    assert ahn1p["binaddr"] == hex2b("deb1f1ffbef6061a0b8f6d23b4e72164b4678253")


def test_ahn1p_subbinaddr(ahn1p) -> None:
    assert "subbinaddr" not in ahn1p


def test_ahn1p_version(ahn1p) -> None:
    assert ahn1p["version"] == "\x6f"


def test_ahn1p_chains(ahn1p) -> None:
    assert len(ahn1p["chains"]) == 1


def test_ahn1p_c0_name(ahn1p) -> None:
    assert ahn1p["chains"][0].name == "Testnet"


def test_ahn1p_balance(ahn1p, gen) -> None:
    assert ahn1p["balance"] == {gen.chain.id: 9.99e8}


def test_ahn1p_txpoints(ahn1p) -> None:
    assert len(ahn1p["txpoints"]) == 1


def test_ahn1p_p0_type(ahn1p) -> None:
    assert ahn1p["txpoints"][0]["type"] == "direct"


def test_ahn1p_p0_is_out(ahn1p) -> None:
    assert not ahn1p["txpoints"][0]["is_out"]


def test_ahn1p_p0_nTime(ahn1p) -> None:
    assert ahn1p["txpoints"][0]["nTime"] == 1231006506


def test_ahn1p_p0_chain(ahn1p) -> None:
    assert ahn1p["txpoints"][0]["chain"].name == "Testnet"


def test_ahn1p_p0_height(ahn1p) -> None:
    assert ahn1p["txpoints"][0]["height"] == 14


def test_ahn1p_p0_blk_hash(ahn1p) -> None:
    assert (
        ahn1p["txpoints"][0]["blk_hash"]
        == "0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e"
    )


def test_ahn1p_p0_tx_hash(ahn1p) -> None:
    assert (
        ahn1p["txpoints"][0]["tx_hash"]
        == "dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52"
    )


def test_ahn1p_p0_pos(ahn1p) -> None:
    assert ahn1p["txpoints"][0]["pos"] == 0


def test_ahn1p_p0_value(ahn1p) -> None:
    assert ahn1p["txpoints"][0]["value"] == 9.99e8


def test_ahn1p_sent(ahn1p, gen) -> None:
    assert ahn1p["sent"] == {gen.chain.id: 0}


def test_ahn1p_received(ahn1p, gen) -> None:
    assert ahn1p["received"] == {gen.chain.id: 9.99e8}


def test_ahn1p_counts(ahn1p) -> None:
    assert ahn1p["counts"] == [1, 0]


@fixture(scope="module")
def a2NFT(gen) -> Optional[Dict[str, Any]]:
    return data.address_history(gen, "2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb")


def test_a2NFT_binaddr(a2NFT) -> None:
    assert a2NFT["binaddr"] == hex2b("f3aae15f9b92a094bb4e01afe99f99ab4135f362")


def test_a2NFT_subbinaddr(a2NFT) -> None:
    assert "subbinaddr" not in a2NFT


def test_a2NFT_version(a2NFT) -> None:
    assert a2NFT["version"] == "\xc4"


def test_a2NFT_chains(a2NFT) -> None:
    assert len(a2NFT["chains"]) == 1


def test_a2NFT_c0_name(a2NFT) -> None:
    assert a2NFT["chains"][0].name == "Testnet"


def test_a2NFT_balance(a2NFT, gen) -> None:
    assert a2NFT["balance"] == {gen.chain.id: 20e8}


def test_a2NFT_txpoints(a2NFT) -> None:
    assert len(a2NFT["txpoints"]) == 1


def test_a2NFT_p0_type(a2NFT) -> None:
    assert a2NFT["txpoints"][0]["type"] == "direct"


def test_a2NFT_p0_is_out(a2NFT) -> None:
    assert not a2NFT["txpoints"][0]["is_out"]


def test_a2NFT_p0_nTime(a2NFT) -> None:
    assert a2NFT["txpoints"][0]["nTime"] == 1231006506


def test_a2NFT_p0_chain(a2NFT) -> None:
    assert a2NFT["txpoints"][0]["chain"].name == "Testnet"


def test_a2NFT_p0_height(a2NFT) -> None:
    assert a2NFT["txpoints"][0]["height"] == 14


def test_a2NFT_p0_blk_hash(a2NFT) -> None:
    assert (
        a2NFT["txpoints"][0]["blk_hash"]
        == "0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e"
    )


def test_a2NFT_p0_tx_hash(a2NFT) -> None:
    assert (
        a2NFT["txpoints"][0]["tx_hash"]
        == "dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52"
    )


def test_a2NFT_p0_pos(a2NFT) -> None:
    assert a2NFT["txpoints"][0]["pos"] == 1


def test_a2NFT_p0_value(a2NFT) -> None:
    assert a2NFT["txpoints"][0]["value"] == 20e8


def test_a2NFT_sent(a2NFT, gen) -> None:
    assert a2NFT["sent"] == {gen.chain.id: 0}


def test_a2NFT_received(a2NFT, gen) -> None:
    assert a2NFT["received"] == {gen.chain.id: 20e8}


def test_a2NFT_counts(a2NFT) -> None:
    assert a2NFT["counts"] == [1, 0]


@fixture(scope="module")
def an3j4(gen) -> Optional[Dict[str, Any]]:
    return data.address_history(gen, "n3j41Rkn51bdfh3NgyaA7x2JKEsfuvq888")


def test_an3j4_binaddr(an3j4) -> None:
    assert an3j4["binaddr"] == pubkey_to_hash(data.PUBKEYS[3])


def test_an3j4_subbinaddr(an3j4) -> None:
    assert "subbinaddr" not in an3j4


def test_an3j4_version(an3j4) -> None:
    assert an3j4["version"] == "\x6f"


def test_an3j4_chains(an3j4) -> None:
    assert len(an3j4["chains"]) == 1


def test_an3j4_c0_name(an3j4) -> None:
    assert an3j4["chains"][0].name == "Testnet"


def test_an3j4_balance(an3j4, gen) -> None:
    assert an3j4["balance"] == {gen.chain.id: 0}


def test_an3j4_txpoints(an3j4) -> None:
    assert len(an3j4["txpoints"]) == 1


def test_an3j4_p0_type(an3j4) -> None:
    assert an3j4["txpoints"][0]["type"] == "escrow"


def test_an3j4_p0_is_out(an3j4) -> None:
    assert not an3j4["txpoints"][0]["is_out"]


def test_an3j4_p0_nTime(an3j4) -> None:
    assert an3j4["txpoints"][0]["nTime"] == 1231006506


def test_an3j4_p0_chain(an3j4) -> None:
    assert an3j4["txpoints"][0]["chain"].name == "Testnet"


def test_an3j4_p0_height(an3j4) -> None:
    assert an3j4["txpoints"][0]["height"] == 14


def test_an3j4_p0_blk_hash(an3j4) -> None:
    assert (
        an3j4["txpoints"][0]["blk_hash"]
        == "0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e"
    )


def test_an3j4_p0_tx_hash(an3j4) -> None:
    assert (
        an3j4["txpoints"][0]["tx_hash"]
        == "dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52"
    )


def test_an3j4_p0_pos(an3j4) -> None:
    assert an3j4["txpoints"][0]["pos"] == 2


def test_an3j4_p0_value(an3j4) -> None:
    assert an3j4["txpoints"][0]["value"] == 20e8


def test_an3j4_sent(an3j4, gen) -> None:
    assert an3j4["sent"] == {gen.chain.id: 0}


def test_an3j4_received(an3j4, gen) -> None:
    assert an3j4["received"] == {gen.chain.id: 0}


def test_an3j4_counts(an3j4) -> None:
    assert an3j4["counts"] == [0, 0]


# TODO: look up multisig by its P2SH address, check subbinaddr.
# TODO: test different types of redeemed outputs.


def b(gen, b) -> Optional[Dict[str, Any]]:
    block = gen.store.export_block(chain=gen.chain, block_number=b)
    return block


@fixture(scope="module")
def b14(gen) -> Optional[Dict[str, Any]]:
    return b(gen, 14)


def test_b14_chain_candidates(b14) -> None:
    assert len(b14["chain_candidates"]) == 1


def test_b14cc0_chain_name(b14) -> None:
    assert b14["chain_candidates"][0]["chain"].name == "Testnet"


def test_b14cc0_in_longest(b14) -> None:
    assert b14["chain_candidates"][0]["in_longest"]


def test_b14_chain_satoshis(b14) -> None:
    assert b14["chain_satoshis"] == 750 * 10 ** 8


def test_b14_chain_satoshi_seconds(b14) -> None:
    assert b14["chain_satoshi_seconds"] == -656822590000000000


def test_b14_chain_work(b14) -> None:
    assert b14["chain_work"] == 64425492495


def test_b14_fees(b14) -> None:
    assert b14["fees"] == 0.01e8


def test_b14_generated(b14) -> None:
    assert b14["generated"] == int(50e8)


def test_b14_hash(b14) -> None:
    assert (
        b14["hash"]
        == "0c2d2879773626a081d74e73b3dcb9276e2a366e4571b2de6d90c2a67295382e"
    )


def test_b14_hashMerkleRoot(b14) -> None:
    assert (
        b14["hashMerkleRoot"]
        == "93f17b59330df6c97f8d305572b0b98608b34a2f4fa235e6ff69bbe343e3a764"
    )


def test_b14_hashPrev(b14) -> None:
    assert (
        b14["hashPrev"]
        == "2155786533653694385a772e33d9547848c809b1d1bce3500a377fe37ad3d250"
    )


def test_b14_height(b14) -> None:
    assert b14["height"] == 14


def test_b14_nBits(b14) -> None:
    assert b14["nBits"] == 0x1D00FFFF


def test_b14_next_block_hashes(b14) -> None:
    assert b14["next_block_hashes"] == []


def test_b14_nNonce(b14) -> None:
    assert b14["nNonce"] == 253


def test_b14_nTime(b14) -> None:
    assert b14["nTime"] == 1231006506


@mark.xfail
def test_b14_satoshis_destroyed(b14) -> None:
    # XXX Is this value right?
    assert b14["satoshis_destroyed"] == -328412110000000000


@mark.xfail
def test_b14_satoshi_seconds(b14) -> None:
    # XXX Is this value right?
    assert b14["satoshi_seconds"] == -328410480000000000


def test_b14_transactions(b14) -> None:
    assert len(b14["transactions"]) == 2


def test_b14_t1_fees(b14) -> None:
    assert b14["transactions"][1]["fees"] == 0.01e8


def test_b14_t1_hash(b14) -> None:
    assert (
        b14["transactions"][1]["hash"]
        == "dd5e827c88eb24502cb74670fa58430e8c51fa6a514c46451829c1896438ce52"
    )


def test_b14_t1_in(b14) -> None:
    assert len(b14["transactions"][1]["in"]) == 1


def test_b14_t1i0_address_version(b14) -> None:
    assert b14["transactions"][1]["in"][0]["address_version"] == "\x6f"


def test_b14_t1i0_binaddr(b14) -> None:
    assert b14["transactions"][1]["in"][0]["binaddr"] == pubkey_to_hash(data.PUBKEYS[1])


def test_b14_t1i0_value(b14) -> None:
    assert b14["transactions"][1]["in"][0]["value"] == int(50e8)


def test_b14_t1_out(b14) -> None:
    assert len(b14["transactions"][1]["out"]) == 3


def test_b14_t1o0_address_version(b14) -> None:
    assert b14["transactions"][1]["out"][0]["address_version"] == "\x6f"


def test_b14_t1o0_binaddr(b14) -> None:
    assert b14["transactions"][1]["out"][0]["binaddr"] == hex2b(
        "deb1f1ffbef6061a0b8f6d23b4e72164b4678253"
    )


def test_b14_t1o0_value(b14) -> None:
    assert b14["transactions"][1]["out"][0]["value"] == 9.99e8


def test_b14_t1o1_address_version(b14) -> None:
    assert b14["transactions"][1]["out"][1]["address_version"] == "\xc4"


def test_b14_t1o1_binaddr(b14) -> None:
    assert b14["transactions"][1]["out"][1]["binaddr"] == hex2b(
        "f3aae15f9b92a094bb4e01afe99f99ab4135f362"
    )


def test_b14_t1o1_value(b14) -> None:
    assert b14["transactions"][1]["out"][1]["value"] == 20e8


def test_b14_t1o2_address_version(b14) -> None:
    assert b14["transactions"][1]["out"][2]["address_version"] == "\x6f"


def test_b14_t1o2_binaddr(b14) -> None:
    assert b14["transactions"][1]["out"][2]["binaddr"] == hex2b(
        "b8bcada90d0992bdc64188d6a0ac3f9fd200d1d1"
    )


def test_b14_t1o2_subbinaddr(b14) -> None:
    assert len(b14["transactions"][1]["out"][2]["subbinaddr"]) == 3


def test_b14_t1o2k0(b14, gen) -> None:
    assert b14["transactions"][1]["out"][2]["subbinaddr"][0] == pubkey_to_hash(
        data.PUBKEYS[2]
    )


def test_b14_t1o2k1(b14, gen) -> None:
    assert b14["transactions"][1]["out"][2]["subbinaddr"][1] == pubkey_to_hash(
        data.PUBKEYS[3]
    )


def test_b14_t1o2k2(b14, gen) -> None:
    assert b14["transactions"][1]["out"][2]["subbinaddr"][2] == pubkey_to_hash(
        data.PUBKEYS[4]
    )


def test_b14_t1o2_required_signatures(b14) -> None:
    assert b14["transactions"][1]["out"][2]["required_signatures"] == 2


def test_b14_t1o2_value(b14) -> None:
    assert b14["transactions"][1]["out"][2]["value"] == 20e8


def test_b14_value_out(b14) -> None:
    assert b14["value_out"] == 100e8


def test_b14_version(b14) -> None:
    assert b14["version"] == 1


def bt(gen, b, t) -> None:
    return gen.store.export_tx(
        tx_hash=gen.blocks[b]["transactions"][t]["hash"][::-1].encode("hex"),
        format="browser",
    )


@fixture(scope="module")
def b14t1(gen) -> None:
    return bt(gen, 14, 1)


def test_b14t1o0_script_type(b14t1) -> None:
    assert b14t1["out"][0]["script_type"] == SCRIPT_TYPE_ADDRESS


def test_b14t1o0_binaddr(b14t1) -> None:
    assert (
        b14t1["out"][0]["binaddr"]
        == decode_address("n1pTUVnjZ6GHxujaoJ62P9NBMNjLr5N2EQ")[1]
    )
    assert b14t1["out"][0]["binaddr"] == hex2b(
        "deb1f1ffbef6061a0b8f6d23b4e72164b4678253"
    )


def test_b14t1o0_value(b14t1) -> None:
    assert b14t1["out"][0]["value"] == 9.99e8


def test_b14t1o1_script_type(b14t1) -> None:
    assert b14t1["out"][1]["script_type"] == SCRIPT_TYPE_P2SH


def test_b14t1o1_binaddr(b14t1) -> None:
    assert (
        b14t1["out"][1]["binaddr"]
        == decode_address("2NFTctsgcAmrgtiboLJUx9q8qu5H1qVpcAb")[1]
    )


def test_b14t1o1_value(b14t1) -> None:
    assert b14t1["out"][1]["value"] == 20e8


def test_b14t1o2_script_type(b14t1) -> None:
    assert b14t1["out"][2]["script_type"] == SCRIPT_TYPE_MULTISIG


def test_b14t1o2_required_signatures(b14t1) -> None:
    assert b14t1["out"][2]["required_signatures"] == 2


def test_b14t1o2_binaddr(b14t1, gen) -> None:
    assert b14t1["out"][2]["binaddr"] == hex2b(
        "b8bcada90d0992bdc64188d6a0ac3f9fd200d1d1"
    )


def test_b14t1o2_subbinaddr(b14t1, gen) -> None:
    assert b14t1["out"][2]["subbinaddr"] == [
        pubkey_to_hash(pubkey) for pubkey in data.PUBKEYS[2:5]
    ]


def test_b14t1o2_value(b14t1) -> None:
    assert b14t1["out"][2]["value"] == 20e8
