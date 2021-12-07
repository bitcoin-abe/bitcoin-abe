"""Base Chain"""

from typing import List, Optional, Tuple, TypedDict, Union
from Abe import util, deserialize
from Abe.constants import PUBKEY_HASH_LENGTH
from Abe.typing import Block, ScriptMultisig, Transaction, opcodes
from Abe.util import NULL_HASH, GENESIS_HASH_PREV
from Abe.streams import BCDataStream

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


class PolicyAttrs(TypedDict, total=False):
    """Type definition for the `BaseChain` `POLICY_ATTRS`"""

    id: int
    name: str
    policy: str
    chain: Optional[str]
    magic: bytes
    code3: str
    address_version: bytes
    decimals: int
    script_addr_vers: bytes


class BaseChain:
    """The basic bitcoin based blockchain methods data structure"""

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
        self.id: int  # pylint: disable=invalid-name
        self.name: str
        self.code3: str
        self.address_version: bytes
        self.script_addr_vers: bytes
        self.magic: bytes
        self.decimals: int
        self.coinbase_prevout_hash: bytes = NULL_HASH
        self.coinbase_prevout_n: int = 0xFFFFFFFF
        self.genesis_hash_prev: bytes = GENESIS_HASH_PREV
        self.datadir_conf_file_name: str = "bitcoin.conf"
        self.datadir_rpcport: int = 8332
        self.datadir_p2pport: int

    def has_feature(self, feature: str) -> bool:  # pylint: disable=unused-argument
        """has_feature"""
        return False

    def is_coinbase_tx(self, transaction: Transaction) -> bool:
        """is_coinbase_tx"""
        return (
            len(transaction["txIn"]) == 1
            and transaction["txIn"][0]["prevout_hash"] == self.coinbase_prevout_hash
        )

    # Chain specific hashing methods
    def block_header_hash(
        self, header: Union[bytes, bytearray, memoryview, None]
    ) -> bytes:
        """block_header_hash"""
        return util.double_sha256(header)

    def transaction_hash(self, transaction: bytes) -> bytes:
        """transaction_hash"""
        return util.double_sha256(transaction)

    # Chain specific data stream wrappers
    def ds_parse_block_header(self, data_stream: BCDataStream) -> Block:
        """ds_parse_block_header"""
        return deserialize.parse_BlockHeader(data_stream)  # type: ignore

    def ds_parse_transaction(self, data_stream: BCDataStream) -> Transaction:
        """ds_parse_transaction"""
        return deserialize.parse_Transaction(data_stream)  # type: ignore

    def ds_parse_block(self, data_stream: BCDataStream) -> Block:
        """ds_parse_block"""
        block: Block = self.ds_parse_block_header(data_stream)
        block["transactions"] = []
        nTransactions: int = (  # pylint: disable=invalid-name
            data_stream.read_compact_size()
        )
        for _ in range(nTransactions):
            block["transactions"].append(self.ds_parse_transaction(data_stream))
        return block

    def ds_block_header_hash(self, data_stream: BCDataStream) -> bytes:
        """For a datastream return the hash of the block header"""
        if isinstance(data_stream.input, (bytes, bytearray, memoryview)):
            return util.double_sha256(
                data_stream.input[
                    data_stream.read_cursor : data_stream.read_cursor + 80
                ]
            )
        return bytes()

    def parse_block_header(self, header: bytes) -> Block:
        """parse_block_header"""
        data_stream: BCDataStream = BCDataStream()
        data_stream.write(header)
        return self.ds_parse_block_header(data_stream)

    def parse_transaction(self, binary_tx: bytes) -> Transaction:
        """parse_transaction"""
        data_stream: BCDataStream = BCDataStream()
        data_stream.write(binary_tx)
        return self.ds_parse_transaction(data_stream)

    def parse_txout_script(self, script):
        """
        Return TYPE, DATA where the format of DATA depends on TYPE.

        * SCRIPT_TYPE_INVALID  - DATA is the raw script
        * SCRIPT_TYPE_UNKNOWN  - DATA is the decoded script
        * SCRIPT_TYPE_PUBKEY   - DATA is the binary public key
        * SCRIPT_TYPE_ADDRESS  - DATA is the binary public key hash
        * SCRIPT_TYPE_BURN     - DATA is None
        * SCRIPT_TYPE_MULTISIG - DATA is {"m":m, "pubkeys":list_of_pubkeys}
        * SCRIPT_TYPE_P2SH     - DATA is the binary script hash
        """
        if script is None:
            raise ValueError()
        try:
            decoded = list(deserialize.script_GetOp(script))
        except (TypeError, ValueError, IndexError):
            return SCRIPT_TYPE_INVALID, script
        return self.parse_decoded_txout_script(decoded)

    def parse_decoded_txout_script(
        self,
        decoded: List[Tuple[int, Optional[bytes]]],
    ) -> Tuple[
        int, Union[bytes, ScriptMultisig, List[Tuple[int, Optional[bytes]]], None]
    ]:
        """parse_decoded_txout_script"""
        if deserialize.match_decoded(decoded, SCRIPT_ADDRESS_TEMPLATE):
            pubkey_hash = decoded[2][1]
            assert pubkey_hash is not None
            if len(pubkey_hash) == PUBKEY_HASH_LENGTH:
                return SCRIPT_TYPE_ADDRESS, pubkey_hash

        elif deserialize.match_decoded(decoded, SCRIPT_PUBKEY_TEMPLATE):
            pubkey = decoded[0][1]
            assert pubkey is not None
            return SCRIPT_TYPE_PUBKEY, pubkey

        elif deserialize.match_decoded(decoded, SCRIPT_P2SH_TEMPLATE):
            script_hash = decoded[1][1]
            assert script_hash is not None and len(script_hash) == PUBKEY_HASH_LENGTH
            return SCRIPT_TYPE_P2SH, script_hash

        elif deserialize.match_decoded(decoded, SCRIPT_BURN_TEMPLATE):
            return SCRIPT_TYPE_BURN, None

        elif len(decoded) >= 4 and decoded[-1][0] == opcodes.OP_CHECKMULTISIG:
            # cf. bitcoin/src/script.cpp:Solver
            n_sig = decoded[-2][0] + 1 - opcodes.OP_1
            m_sig = decoded[0][0] + 1 - opcodes.OP_1
            if (
                1 <= m_sig <= n_sig <= MAX_MULTISIG_KEYS
                and len(decoded) == 3 + n_sig
                and all(
                    [decoded[i][0] <= opcodes.OP_PUSHDATA4 for i in range(1, 1 + n_sig)]
                )
            ):
                return SCRIPT_TYPE_MULTISIG, {
                    "m": m_sig,
                    "pubkeys": [
                        decoded[i][1] if decoded[i][1] is not None else b""  # type: ignore
                        for i in range(1, 1 + n_sig)
                    ],
                }

        # Namecoin overrides this to accept name operations.
        return SCRIPT_TYPE_UNKNOWN, decoded
