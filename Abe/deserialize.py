#
#
#

from socket import socket
import time
import struct
from .enumeration import Enumeration
from .base58 import public_key_to_bc_address, hash_160_to_bc_address
from .util import short_hex, long_hex


def parse_CAddress(vds):
    data = {}
    data["nVersion"] = vds.read_int32()
    data["nTime"] = vds.read_uint32()
    data["nServices"] = vds.read_uint64()
    data["pchReserved"] = vds.read_bytes(12)
    data["ip"] = socket.inet_ntoa(vds.read_bytes(4))
    data["port"] = socket.htons(vds.read_uint16())
    return data


def deserialize_CAddress(data):
    return f"{data['ip']}:{str(data['port'])} (lastseen: {time.ctime(data['nTime'])})"


def parse_setting(setting, vds):
    if setting[0] == "f":  # flag (boolean) settings
        return str(vds.read_boolean())
    if setting == "addrIncoming":
        return ""  # bitcoin 0.4 purposely breaks addrIncoming setting in encrypted wallets.
    if setting[0:4] == "addr":  # CAddress
        data = parse_CAddress(vds)
        return deserialize_CAddress(data)
    if setting == "nTransactionFee":
        return vds.read_int64()
    if setting == "nLimitProcessors":
        return vds.read_int32()
    return "unknown setting"


def parse_TxIn(vds):
    data = {}
    data["prevout_hash"] = vds.read_bytes(32)
    data["prevout_n"] = vds.read_uint32()
    data["scriptSig"] = vds.read_bytes(vds.read_compact_size())
    data["sequence"] = vds.read_uint32()
    return data


def deserialize_TxIn(data, transaction_index=None, owner_keys=None):
    if data["prevout_hash"] == b"\x00" * 32:
        result = "TxIn: COIN GENERATED"
        result += " coinbase:" + data["scriptSig"].encode("hex_codec")
    elif transaction_index is not None and data["prevout_hash"] in transaction_index:
        prevout = transaction_index[data["prevout_hash"]]["txOut"][data["prevout_n"]]
        result = f"TxIn: value: {prevout['value'] / 1.0e8}"
        result += (
            " prev("
            + long_hex(data["prevout_hash"][::-1])
            + ":"
            + str(data["prevout_n"])
            + ")"
        )
    else:
        result = (
            "TxIn: prev("
            + long_hex(data["prevout_hash"][::-1])
            + ":"
            + str(data["prevout_n"])
            + ")"
        )
        pub_key = extract_public_key(data["scriptSig"])
        result += " pubkey: " + pub_key
        result += " sig: " + decode_script(data["scriptSig"])
    if data["sequence"] < 0xFFFFFFFF:
        result += " sequence: " + hex(data["sequence"])
    return result


def parse_TxOut(vds):
    data = {}
    data["value"] = vds.read_int64()
    data["scriptPubKey"] = vds.read_bytes(vds.read_compact_size())
    return data


def deserialize_TxOut(data, owner_keys=None):
    result = f"TxOut: value: {data['value'] / 1.0e8}"
    pub_key = extract_public_key(data["scriptPubKey"])
    result += " pubkey: " + pub_key
    result += " Script: " + decode_script(data["scriptPubKey"])
    if owner_keys is not None:
        if pub_key in owner_keys:
            result += " Own: True"
        else:
            result += " Own: False"
    return result


def parse_Transaction(vds, has_nTime=False):
    # pylint: disable=unused-variable
    data = {}
    start_pos = vds.read_cursor
    data["version"] = vds.read_int32()
    if has_nTime:
        data["nTime"] = vds.read_uint32()
    n_vin = vds.read_compact_size()
    data["txIn"] = []
    for i in range(n_vin):
        data["txIn"].append(parse_TxIn(vds))
    n_vout = vds.read_compact_size()
    data["txOut"] = []
    for i in range(n_vout):
        data["txOut"].append(parse_TxOut(vds))
    data["lockTime"] = vds.read_uint32()
    data["__data__"] = vds.input[start_pos : vds.read_cursor]
    return data


def deserialize_Transaction(
    data, transaction_index=None, owner_keys=None, print_raw_tx=False
):
    result = f"{len(data['txIn'])} tx in, {len(data['txOut'])} out\n"
    for txIn in data["txIn"]:
        result += deserialize_TxIn(txIn, transaction_index) + "\n"
    for txOut in data["txOut"]:
        result += deserialize_TxOut(txOut, owner_keys) + "\n"
    if print_raw_tx is True:
        result += "Transaction hex value: " + data["__data__"].encode("hex") + "\n"

    return result


def parse_MerkleTx(vds):
    data = parse_Transaction(vds)
    data["hashBlock"] = vds.read_bytes(32)
    n_merkle_branch = vds.read_compact_size()
    data["merkleBranch"] = vds.read_bytes(32 * n_merkle_branch)
    data["nIndex"] = vds.read_int32()
    return data


def deserialize_MerkleTx(data, transaction_index=None, owner_keys=None):
    tx = deserialize_Transaction(data, transaction_index, owner_keys)
    result = "block: " + (data["hashBlock"][::-1]).encode("hex_codec")
    result += f" {len(data['merkleBranch']) / 32} hashes in merkle branch\n"
    return result + tx


def parse_WalletTx(vds):
    # pylint: disable=unused-variable
    data = parse_MerkleTx(vds)
    n_vtxPrev = vds.read_compact_size()
    data["vtxPrev"] = []
    for i in range(n_vtxPrev):
        data["vtxPrev"].append(parse_MerkleTx(vds))

    data["mapValue"] = {}
    n_mapValue = vds.read_compact_size()
    for i in range(n_mapValue):
        key = vds.read_string()
        value = vds.read_string()
        data["mapValue"][key] = value
    n_orderForm = vds.read_compact_size()
    data["orderForm"] = []
    for i in range(n_orderForm):
        first = vds.read_string()
        second = vds.read_string()
        data["orderForm"].append((first, second))
    data["fTimeReceivedIsTxTime"] = vds.read_uint32()
    data["timeReceived"] = vds.read_uint32()
    data["fromMe"] = vds.read_boolean()
    data["spent"] = vds.read_boolean()

    return data


def deserialize_WalletTx(data, transaction_index=None, owner_keys=None):
    result = deserialize_MerkleTx(data, transaction_index, owner_keys)
    result += f"{len(data['vtxPrev'])} vtxPrev txns\n"
    result += "mapValue:" + str(data["mapValue"])
    if len(data["orderForm"]) > 0:
        result += "\n" + " orderForm:" + str(data["orderForm"])
    result += "\n" + "timeReceived:" + time.ctime(data["timeReceived"])
    result += " fromMe:" + str(data["fromMe"]) + " spent:" + str(data["spent"])
    return result


# The CAuxPow (auxiliary proof of work) structure supports merged mining.
# A flag in the block version field indicates the structure's presence.
# As of 8/2011, the Original Bitcoin Client does not use it.  CAuxPow
# originated in Namecoin; see
# https://github.com/vinced/namecoin/blob/mergedmine/doc/README_merged-mining.md.
def parse_AuxPow(vds):
    data = parse_MerkleTx(vds)
    n_chainMerkleBranch = vds.read_compact_size()
    data["chainMerkleBranch"] = vds.read_bytes(32 * n_chainMerkleBranch)
    data["chainIndex"] = vds.read_int32()
    data["parentBlock"] = parse_BlockHeader(vds)
    return data


def parse_BlockHeader(vds):
    data = {}
    header_start = vds.read_cursor
    data["version"] = vds.read_int32()
    data["hashPrev"] = vds.read_bytes(32)
    data["hashMerkleRoot"] = vds.read_bytes(32)
    data["nTime"] = vds.read_uint32()
    data["nBits"] = vds.read_uint32()
    data["nNonce"] = vds.read_uint32()
    header_end = vds.read_cursor
    data["__header__"] = vds.input[header_start:header_end]
    return data


def parse_Block(vds):
    # pylint: disable=unused-variable
    data = parse_BlockHeader(vds)
    data["transactions"] = []
    #  if data['version'] & (1 << 8):
    #    data['auxpow'] = parse_AuxPow(vds)
    nTransactions = vds.read_compact_size()
    for i in range(nTransactions):
        data["transactions"].append(parse_Transaction(vds))

    return data


def deserialize_Block(data, print_raw_tx=False):
    result = "Time: " + time.ctime(data["nTime"]) + " Nonce: " + str(data["nNonce"])
    result += "\nnBits: 0x" + hex(data["nBits"])
    result += "\nhashMerkleRoot: 0x" + data["hashMerkleRoot"][::-1].encode("hex_codec")
    result += "\nPrevious block: " + data["hashPrev"][::-1].encode("hex_codec")
    result += f"\n{len(data['transactions'])} transactions:\n"
    for txn in data["transactions"]:
        result += deserialize_Transaction(txn, print_raw_tx=print_raw_tx) + "\n"
    result += "\nRaw block header: " + data["__header__"].encode("hex_codec")
    return result


def parse_BlockLocator(vds):
    # pylint: disable=unused-variable
    data = {"hashes": []}
    nHashes = vds.read_compact_size()
    for i in range(nHashes):
        data["hashes"].append(vds.read_bytes(32))
    return data


def deserialize_BlockLocator(data):
    result = "Block Locator top: " + data["hashes"][0][::-1].encode("hex_codec")
    return result


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


def script_GetOp(_bytes):
    i = 0
    while i < len(_bytes):
        vch = None
        opcode = ord(_bytes[i])
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                if i + 1 > len(_bytes):
                    vch = "_INVALID_NULL"
                    i = len(_bytes)
                else:
                    nSize = ord(_bytes[i])
                    i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                if i + 2 > len(_bytes):
                    vch = "_INVALID_NULL"
                    i = len(_bytes)
                else:
                    (nSize,) = struct.unpack_from(  # pylint: disable=no-member
                        "<H", _bytes, i
                    )
                    i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                if i + 4 > len(_bytes):
                    vch = "_INVALID_NULL"
                    i = len(_bytes)
                else:
                    (nSize,) = struct.unpack_from(  # pylint: disable=no-member
                        "<I", _bytes, i
                    )
                    i += 4
            if i + nSize > len(_bytes):
                vch = "_INVALID_" + _bytes[i:]
                i = len(_bytes)
            else:
                vch = _bytes[i : i + nSize]
                i += nSize
        elif opcodes.OP_1 <= opcode <= opcodes.OP_16:
            vch = chr(opcode - opcodes.OP_1 + 1)
        elif opcode == opcodes.OP_1NEGATE:
            vch = chr(255)

        yield (opcode, vch)


def script_GetOpName(opcode):
    try:
        return (opcodes.whatis(opcode)).replace("OP_", "")
    except KeyError:
        return "InvalidOp_" + str(opcode)


def decode_script(_bytes):
    result = ""
    for (opcode, vch) in script_GetOp(_bytes):
        if len(result) > 0:
            result += " "
        if opcode <= opcodes.OP_PUSHDATA4:
            result += f"{opcode}:"
            result += short_hex(vch)
        else:
            result += script_GetOpName(opcode)
    return result


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False
    for i in enumerate(decoded):
        if (
            to_match[i] == opcodes.OP_PUSHDATA4
            and decoded[i][0] <= opcodes.OP_PUSHDATA4
        ):
            # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
            continue
        if to_match[i] != decoded[i][0]:
            return False
    return True


def extract_public_key(_bytes, version="\x00"):
    try:
        decoded = list(script_GetOp(_bytes))
    except struct.error:  # pylint: disable=no-member
        return "(None)"

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (33 or 65 bytes) onto the stack:
    match = [opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4]
    if match_decoded(decoded, match):
        return public_key_to_bc_address(decoded[1][1], version=version)

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match = [opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG]
    if match_decoded(decoded, match):
        return public_key_to_bc_address(decoded[0][1], version=version)

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match = [
        opcodes.OP_DUP,
        opcodes.OP_HASH160,
        opcodes.OP_PUSHDATA4,
        opcodes.OP_EQUALVERIFY,
        opcodes.OP_CHECKSIG,
    ]
    if match_decoded(decoded, match):
        return hash_160_to_bc_address(decoded[2][1], version=version)

    # BIP11 TxOuts look like one of these:
    multisigs = [
        [
            opcodes.OP_PUSHDATA4,
            opcodes.OP_PUSHDATA4,
            opcodes.OP_1,
            opcodes.OP_CHECKMULTISIG,
        ],
        [
            opcodes.OP_PUSHDATA4,
            opcodes.OP_PUSHDATA4,
            opcodes.OP_PUSHDATA4,
            opcodes.OP_2,
            opcodes.OP_CHECKMULTISIG,
        ],
        [
            opcodes.OP_PUSHDATA4,
            opcodes.OP_PUSHDATA4,
            opcodes.OP_PUSHDATA4,
            opcodes.OP_PUSHDATA4,
            opcodes.OP_3,
            opcodes.OP_CHECKMULTISIG,
        ],
    ]
    for match in multisigs:
        if match_decoded(decoded, match):
            return (
                "["
                + ",".join(
                    [
                        public_key_to_bc_address(decoded[i][1])
                        for i in range(1, len(decoded) - 1)
                    ]
                )
                + "]"
            )

    # BIP16 TxOuts look like:
    # HASH160 20 BYTES:... EQUAL
    match = [opcodes.OP_HASH160, 0x14, opcodes.OP_EQUAL]
    if match_decoded(decoded, match):
        return hash_160_to_bc_address(decoded[1][1], version="\x05")

    return "(None)"
