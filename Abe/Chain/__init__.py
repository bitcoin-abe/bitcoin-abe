# Copyright(C) 2014 by Abe developers.

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

from .. import deserialize, util
from ..deserialize import opcodes
from ..streams import BCDataStream


def create(policy, **kwargs):
    mod = __import__(__name__ + "." + policy, fromlist=[policy])
    cls = getattr(mod, policy)
    return cls(policy=policy, **kwargs)


PUBKEY_HASH_LENGTH = 20
MAX_MULTISIG_KEYS = 3

# Template to match a pubkey hash ("Bitcoin address transaction") in
# txout_scriptPubKey.  OP_PUSHDATA4 matches any data push.
SCRIPT_ADDRESS_TEMPLATE = [
    opcodes.OP_DUP,
    opcodes.OP_HASH160,
    opcodes.OP_PUSHDATA4,
    opcodes.OP_EQUALVERIFY,
    opcodes.OP_CHECKSIG,
]

# Template to match a pubkey ("IP address transaction") in txout_scriptPubKey.
SCRIPT_PUBKEY_TEMPLATE = [opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG]

# Template to match a BIP16 pay-to-script-hash (P2SH) output script.
SCRIPT_P2SH_TEMPLATE = [opcodes.OP_HASH160, PUBKEY_HASH_LENGTH, opcodes.OP_EQUAL]

# Template to match a script that can never be redeemed, used in Namecoin.
SCRIPT_BURN_TEMPLATE = [opcodes.OP_RETURN]

SCRIPT_TYPE_INVALID = 0
SCRIPT_TYPE_UNKNOWN = 1
SCRIPT_TYPE_PUBKEY = 2
SCRIPT_TYPE_ADDRESS = 3
SCRIPT_TYPE_BURN = 4
SCRIPT_TYPE_MULTISIG = 5
SCRIPT_TYPE_P2SH = 6


class BaseChain:
    POLICY_ATTRS = [
        "magic",
        "name",
        "code3",
        "address_version",
        "decimals",
        "script_addr_vers",
    ]
    __all__ = ["id", "policy"] + POLICY_ATTRS

    def __init__(self, src=None, **kwargs):
        for attr in self.__all__:
            if attr in kwargs:
                val = kwargs.get(attr)
            elif hasattr(self, attr):
                continue
            elif src is not None:
                val = getattr(src, attr)
            else:
                val = None
            setattr(self, attr, val)

    def has_feature(self, feature):  # pylint: disable=unused-argument
        return False

    def ds_parse_block_header(self, ds):
        return deserialize.parse_BlockHeader(ds)

    def ds_parse_transaction(self, ds):
        return deserialize.parse_Transaction(ds)

    def ds_parse_block(self, ds):
        d = self.ds_parse_block_header(ds)
        d["transactions"] = []
        nTransactions = ds.read_compact_size()
        for i in range(nTransactions):
            d["transactions"].append(self.ds_parse_transaction(ds))
        return d

    def ds_serialize_block(self, ds, block):
        self.ds_serialize_block_header(ds, block)
        ds.write_compact_size(len(block["transactions"]))
        for tx in block["transactions"]:
            self.ds_serialize_transaction(ds, tx)

    def ds_serialize_block_header(self, ds, block):
        ds.write_int32(block["version"])
        ds.write(block["hashPrev"])
        ds.write(block["hashMerkleRoot"])
        ds.write_uint32(block["nTime"])
        ds.write_uint32(block["nBits"])
        ds.write_uint32(block["nNonce"])

    def ds_serialize_transaction(self, ds, tx):
        ds.write_int32(tx["version"])
        ds.write_compact_size(len(tx["txIn"]))
        for txin in tx["txIn"]:
            self.ds_serialize_txin(ds, txin)
        ds.write_compact_size(len(tx["txOut"]))
        for txout in tx["txOut"]:
            self.ds_serialize_txout(ds, txout)
        ds.write_uint32(tx["lockTime"])

    def ds_serialize_txin(self, ds, txin):
        ds.write(txin["prevout_hash"])
        ds.write_uint32(txin["prevout_n"])
        ds.write_string(txin["scriptSig"])
        ds.write_uint32(txin["sequence"])

    def ds_serialize_txout(self, ds, txout):
        ds.write_int64(txout["value"])
        ds.write_string(txout["scriptPubKey"])

    def serialize_block(self, block):
        ds = BCDataStream()
        self.ds_serialize_block(ds, block)
        return ds.input

    def serialize_block_header(self, block):
        ds = BCDataStream()
        self.ds_serialize_block_header(ds, block)
        return ds.input

    def serialize_transaction(self, tx):
        ds = BCDataStream()
        self.ds_serialize_transaction(ds, tx)
        return ds.input

    def block_header_hash(self, header):
        """This is a prototype."""

    def ds_block_header_hash(self, ds):
        return self.block_header_hash(ds.input[ds.read_cursor : ds.read_cursor + 80])

    def transaction_hash(self, binary_tx):
        return util.double_sha256(binary_tx)

    def merkle_hash(self, hashes):
        return util.double_sha256(hashes)

    # Based on CBlock::BuildMerkleTree().
    def merkle_root(self, hashes):
        while len(hashes) > 1:
            size = len(hashes)
            out = []
            for i in range(0, size, 2):
                i2 = min(i + 1, size - 1)
                out.append(self.merkle_hash(hashes[i] + hashes[i2]))
            hashes = out
        return hashes and hashes[0]

    def parse_block_header(self, header):
        return self.ds_parse_block_header(util.str_to_ds(header))

    def parse_transaction(self, binary_tx):
        return self.ds_parse_transaction(util.str_to_ds(binary_tx))

    def is_coinbase_tx(self, tx):
        return (
            len(tx["txIn"]) == 1
            and tx["txIn"][0]["prevout_hash"] == self.coinbase_prevout_hash
        )

    coinbase_prevout_hash = util.NULL_HASH
    coinbase_prevout_n = 0xFFFFFFFF
    genesis_hash_prev = util.GENESIS_HASH_PREV

    def parse_txout_script(self, script):
        """
        Return TYPE, DATA where the format of DATA depends on TYPE.

        * SCRIPT_TYPE_INVALID  - DATA is the raw script
        * SCRIPT_TYPE_UNKNOWN  - DATA is the decoded script
        * SCRIPT_TYPE_PUBKEY   - DATA is the binary public key
        * SCRIPT_TYPE_ADDRESS  - DATA is the binary public key hash
        * SCRIPT_TYPE_BURN     - DATA is None
        * SCRIPT_TYPE_MULTISIG - DATA is {"m":M, "pubkeys":list_of_pubkeys}
        * SCRIPT_TYPE_P2SH     - DATA is the binary script hash
        """
        if script is None:
            raise ValueError()
        try:
            decoded = list(deserialize.script_GetOp(script))
        except Exception:
            return SCRIPT_TYPE_INVALID, script
        return self.parse_decoded_txout_script(decoded)

    def parse_decoded_txout_script(self, decoded):
        if deserialize.match_decoded(decoded, SCRIPT_ADDRESS_TEMPLATE):
            pubkey_hash = decoded[2][1]
            if len(pubkey_hash) == PUBKEY_HASH_LENGTH:
                return SCRIPT_TYPE_ADDRESS, pubkey_hash

        elif deserialize.match_decoded(decoded, SCRIPT_PUBKEY_TEMPLATE):
            pubkey = decoded[0][1]
            return SCRIPT_TYPE_PUBKEY, pubkey

        elif deserialize.match_decoded(decoded, SCRIPT_P2SH_TEMPLATE):
            script_hash = decoded[1][1]
            assert len(script_hash) == PUBKEY_HASH_LENGTH
            return SCRIPT_TYPE_P2SH, script_hash

        elif deserialize.match_decoded(decoded, SCRIPT_BURN_TEMPLATE):
            return SCRIPT_TYPE_BURN, None

        elif len(decoded) >= 4 and decoded[-1][0] == opcodes.OP_CHECKMULTISIG:
            # cf. bitcoin/src/script.cpp:Solver
            n = decoded[-2][0] + 1 - opcodes.OP_1
            m = decoded[0][0] + 1 - opcodes.OP_1
            if (
                1 <= m <= n <= MAX_MULTISIG_KEYS
                and len(decoded) == 3 + n
                and all(
                    [decoded[i][0] <= opcodes.OP_PUSHDATA4 for i in range(1, 1 + n)]
                )
            ):
                return SCRIPT_TYPE_MULTISIG, {
                    "m": m,
                    "pubkeys": [decoded[i][1] for i in range(1, 1 + n)],
                }

        # Namecoin overrides this to accept name operations.
        return SCRIPT_TYPE_UNKNOWN, decoded

    def pubkey_hash(self, pubkey):
        return util.pubkey_to_hash(pubkey)

    def script_hash(self, script):
        return self.pubkey_hash(script)

    datadir_conf_file_name = "bitcoin.conf"
    datadir_rpcport = 8332
