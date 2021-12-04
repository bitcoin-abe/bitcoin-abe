"""A library containing all of the types used in Abe"""

from typing import TypedDict, List, Dict, Tuple, Optional, Union
from Abe.enumeration import Enumeration


class TxIn(TypedDict, total=False):
    """TxIn Dictionary Type"""

    prevout_hash: bytes
    prevout_n: int
    scriptSig: bytes
    sequence: int


class TxOut(TypedDict, total=False):
    """TxOut Dictionary Type"""

    value: int
    scriptPubKey: bytes


class Witness(TypedDict):
    """Witness Dictionary Type"""

    witness: bytes


class Transaction(TypedDict, total=False):
    """Transaction Dictionary Type"""

    version: int
    nTime: Optional[bytes]  # This is for some alt.
    marker: Optional[bytes]  # SegWit marker
    flag: Optional[bytes]  # SegWit flag
    txIn: List[TxIn]
    txOut: List[TxOut]
    witness: Optional[List[Witness]]  # segregated witness
    lockTime: int
    __data__: Union[bytearray, memoryview, None]


class MerkleTx(Transaction, total=False):
    """Merkle Transaction Dictionary Type"""

    hashBlock: bytes
    merkleBranch: bytes
    nIndex: int


class WalletTx(MerkleTx, total=False):
    """Wallet Transaction Dictionary Type"""

    vtxPrev: List[MerkleTx]
    mapValue: Dict[bytes, bytes]
    orderForm: List[Tuple[bytes, bytes]]
    fTimeReceivedIsTxTime: int
    timeReceived: int
    fromMe: bool
    spent: bool


class BlockHeader(TypedDict, total=False):
    """Block Dictionary Type"""

    version: int
    hashPrev: bytes
    hashMerkleRoot: bytes
    nTime: int
    nBits: int
    nNonce: int
    __header__: bytes


class Block(BlockHeader, total=False):
    """Block Dictionary Type"""

    transactions: List[Transaction]


class CAddress(TypedDict):
    """CAddress Dictionary Type"""

    nVersion: int
    nTime: int
    nServices: int
    pchReserved: bytes
    ip: str
    port: int


opcodes = Enumeration(
    "Opcodes",
    [
        ("OP_0", 0),
        ("OP_PUSHDATA1", 76),
        "OP_PUSHDATA2",
        "OP_PUSHDATA4",
        "OP_1NEGATE",
        "OP_RESERVED",
        "OP_1",
        "OP_2",
        "OP_3",
        "OP_4",
        "OP_5",
        "OP_6",
        "OP_7",
        "OP_8",
        "OP_9",
        "OP_10",
        "OP_11",
        "OP_12",
        "OP_13",
        "OP_14",
        "OP_15",
        "OP_16",
        "OP_NOP",
        "OP_VER",
        "OP_IF",
        "OP_NOTIF",
        "OP_VERIF",
        "OP_VERNOTIF",
        "OP_ELSE",
        "OP_ENDIF",
        "OP_VERIFY",
        "OP_RETURN",
        "OP_TOALTSTACK",
        "OP_FROMALTSTACK",
        "OP_2DROP",
        "OP_2DUP",
        "OP_3DUP",
        "OP_2OVER",
        "OP_2ROT",
        "OP_2SWAP",
        "OP_IFDUP",
        "OP_DEPTH",
        "OP_DROP",
        "OP_DUP",
        "OP_NIP",
        "OP_OVER",
        "OP_PICK",
        "OP_ROLL",
        "OP_ROT",
        "OP_SWAP",
        "OP_TUCK",
        "OP_CAT",
        "OP_SUBSTR",
        "OP_LEFT",
        "OP_RIGHT",
        "OP_SIZE",
        "OP_INVERT",
        "OP_AND",
        "OP_OR",
        "OP_XOR",
        "OP_EQUAL",
        "OP_EQUALVERIFY",
        "OP_RESERVED1",
        "OP_RESERVED2",
        "OP_1ADD",
        "OP_1SUB",
        "OP_2MUL",
        "OP_2DIV",
        "OP_NEGATE",
        "OP_ABS",
        "OP_NOT",
        "OP_0NOTEQUAL",
        "OP_ADD",
        "OP_SUB",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
        "OP_LSHIFT",
        "OP_RSHIFT",
        "OP_BOOLAND",
        "OP_BOOLOR",
        "OP_NUMEQUAL",
        "OP_NUMEQUALVERIFY",
        "OP_NUMNOTEQUAL",
        "OP_LESSTHAN",
        "OP_GREATERTHAN",
        "OP_LESSTHANOREQUAL",
        "OP_GREATERTHANOREQUAL",
        "OP_MIN",
        "OP_MAX",
        "OP_WITHIN",
        "OP_RIPEMD160",
        "OP_SHA1",
        "OP_SHA256",
        "OP_HASH160",
        "OP_HASH256",
        "OP_CODESEPARATOR",
        "OP_CHECKSIG",
        "OP_CHECKSIGVERIFY",
        "OP_CHECKMULTISIG",
        "OP_CHECKMULTISIGVERIFY",
        "OP_NOP1",
        "OP_CHECKLOCKTIMEVERIFY",
        "OP_CHECKSEQUENCEVERIFY",
        "OP_NOP4",
        "OP_NOP5",
        "OP_NOP6",
        "OP_NOP7",
        "OP_NOP8",
        "OP_NOP9",
        "OP_NOP10",
        ("OP_INVALIDOPCODE", 0xFF),
    ],
)
