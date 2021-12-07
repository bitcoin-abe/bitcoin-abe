"""Deserialize the Block Data"""


import socket
import struct
import time
from typing import Dict, Generator, List, Optional, Tuple, Union
from .streams import BCDataStream
from .base58 import public_key_to_bc_address, hash_160_to_bc_address
from .typing import (
    CAddress,
    TxIn,
    TxOut,
    Transaction,
    MerkleTx,
    WalletTx,
    Block,
    Witness,
    opcodes,
)
from .util import b2hex, short_hex, long_hex

# pylint:disable=invalid-name


def parse_CAddress(data_stream: BCDataStream) -> CAddress:
    """Parse the address into the"""
    # pylint: disable=no-member
    data: CAddress = {
        "nVersion": data_stream.read_int32(),
        "nTime": data_stream.read_uint32(),
        "nServices": data_stream.read_uint64(),
        "pchReserved": data_stream.read_bytes(12),
        "ip": socket.inet_ntoa(data_stream.read_bytes(4)),
        "port": socket.htons(data_stream.read_uint16()),
    }
    return data


def deserialize_CAddress(data) -> str:
    """Deserialize the CAddress dict to return the address string."""
    return f"{data['ip']}:{str(data['port'])} (lastseen: {time.ctime(data['nTime'])})"


def parse_setting(
    setting: Union[List[str], str], data_stream: BCDataStream
) -> Union[str, int]:
    """Parse the setting data stream to either an int or a str"""
    if setting[0] == "f":  # flag (boolean) settings
        return str(data_stream.read_boolean())
    if setting == "addrIncoming":
        return ""  # bitcoin 0.4 purposely breaks addrIncoming setting in encrypted wallets.
    if setting[0:4] == "addr":  # CAddress
        data = parse_CAddress(data_stream)
        return deserialize_CAddress(data)
    if setting == "nTransactionFee":
        return data_stream.read_int64()  # type: ignore
    if setting == "nLimitProcessors":
        return data_stream.read_int32()  # type: ignore
    return "unknown setting"


def parse_TxIn(data_stream: BCDataStream) -> TxIn:
    """Parse the Tx data stream into a dict."""
    data: TxIn = {
        "prevout_hash": data_stream.read_bytes(32),
        "prevout_n": data_stream.read_uint32(),
        "scriptSig": data_stream.read_bytes(data_stream.read_compact_size()),
        "sequence": data_stream.read_uint32(),
    }
    return data


def deserialize_TxIn(data: TxIn, transaction_index=None) -> str:
    """Deserialize the Tx dict to a string."""
    if data["prevout_hash"] == b"\x00" * 32:
        result = "Tx: COIN GENERATED"
        result += " coinbase:" + b2hex(data["scriptSig"])
    elif transaction_index is not None and data["prevout_hash"] in transaction_index:
        prevout = transaction_index[data["prevout_hash"]]["txOut"][data["prevout_n"]]
        result = f"Tx: value: {prevout['value'] / 1.0e8}"
        result += (
            " prev("
            + long_hex(data["prevout_hash"][::-1])
            + ":"
            + str(data["prevout_n"])
            + ")"
        )
    else:
        result = (
            "Tx: prev("
            + long_hex(data["prevout_hash"][::-1])
            + ":"
            + str(data["prevout_n"])
            + ")"
        )
        pub_key = extract_public_key(data["scriptSig"])
        if isinstance(pub_key, bytes):
            result += " pubkey: " + b2hex(pub_key)
        else:
            pass  # XXX This needs to be filled in to support multisig
        result += " sig: " + decode_script(data["scriptSig"])
    if data["sequence"] < 0xFFFFFFFF:
        result += " sequence: " + hex(data["sequence"])
    return result


def parse_TxOut(data_stream: BCDataStream) -> TxOut:
    """Parse the Tx stream data to dict."""
    data: TxOut = {
        "value": data_stream.read_int64(),
        "scriptPubKey": data_stream.read_bytes(data_stream.read_compact_size()),
    }
    return data


def deserialize_TxOut(data: TxOut, owner_keys=None) -> str:
    """Deserialize a Tx from a dict to a string"""
    result = f"Tx: value: {data['value'] / 1.0e8}"
    pub_key = extract_public_key(data["scriptPubKey"])
    if isinstance(pub_key, bytes):
        result += " pubkey: " + b2hex(pub_key)
    else:
        pass  # XXX This needs to be filled in to support multisig
    result += " Script: " + decode_script(data["scriptPubKey"])
    if owner_keys is not None:
        if pub_key in owner_keys:
            result += " Own: True"
        else:
            result += " Own: False"
    return result


def has_extended_format(data_stream: BCDataStream) -> bool:
    """Determine if the transaction uses a segregated witness

    Args:
        data_stream (BCDataStream): block data stream

    Returns:
        bool: True if the BIP 144 marker is present
    """
    marker: bytes = data_stream.read_marker()
    return marker == b"\x00"


def parse_scriptWitness(data_stream: BCDataStream) -> bytes:
    """Parse the witness stream data to dict"""
    witness: Witness = {
        "witness": data_stream.read_bytes(data_stream.read_compact_size())
    }
    return witness["witness"]


def parse_Transaction(data_stream: BCDataStream, has_nTime=False) -> Transaction:
    """Parse a transaction from the data stream into a dict"""
    # The structure is taken from:
    # https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki

    if data_stream.input is None:
        raise IOError

    start_pos: int = data_stream.read_cursor
    nVersion: int = data_stream.read_int32()

    if has_nTime:
        nTime: Optional[int] = data_stream.read_uint32()
    else:
        nTime = None

    if has_extended_format(data_stream):
        marker: Optional[bytes] = data_stream.read_bytes(1)
        flag: Optional[bytes] = data_stream.read_bytes(1)
    else:
        marker = None
        flag = None

    n_vin: int = data_stream.read_compact_size()
    txins: List[TxIn] = []

    for _ in range(n_vin):
        txins.append(parse_TxIn(data_stream))

    n_vout = data_stream.read_compact_size()
    txouts: List[TxOut] = []

    for _ in range(n_vout):
        txouts.append(parse_TxOut(data_stream))

    if marker is not None and flag == b"\x01":
        script_witnesses: Optional[List[bytes]] = []
        assert script_witnesses is not None

        for _ in range(n_vin):
            script_witnesses.append(parse_scriptWitness(data_stream))
    else:
        script_witnesses = None

    lockTime: int = data_stream.read_uint32()
    stream_data = data_stream.input[start_pos : data_stream.read_cursor]

    data: Transaction = {
        "version": nVersion,
        "nTime": nTime,
        "marker": marker,
        "flag": flag,
        "txIn": txins,
        "txOut": txouts,
        "scriptWitnesses": script_witnesses,
        "lockTime": lockTime,
        "__data__": bytes(stream_data),
    }

    return data


def deserialize_Transaction(
    data: Transaction, transaction_index=None, owner_keys=None, print_raw_tx=False
) -> str:
    """Deserialize a transaction from the dict into a str."""

    result = f"{len(data['txIn'])} tx in, {len(data['txOut'])} out\n"
    for txIn in data["txIn"]:
        result += deserialize_TxIn(txIn, transaction_index) + "\n"
    for txOut in data["txOut"]:
        result += deserialize_TxOut(txOut, owner_keys) + "\n"
    if print_raw_tx is True:
        if data["__data__"] is not None:
            result += "Transaction hex value: " + b2hex(data["__data__"]) + "\n"

    return result


def parse_MerkleTx(data_stream: BCDataStream) -> MerkleTx:
    """Parse the MerkleTx into a Transaction dict form the data stream"""
    data: MerkleTx = {}
    parse_Transaction(data_stream)
    data["hashBlock"] = data_stream.read_bytes(32)
    n_merkle_branch = data_stream.read_compact_size()
    data["merkleBranch"] = data_stream.read_bytes(32 * n_merkle_branch)
    data["nIndex"] = data_stream.read_int32()
    return data


def deserialize_MerkleTx(
    data: MerkleTx, transaction_index=None, owner_keys=None
) -> str:
    """Deserialize the MerkleTx dict to a string"""
    tx = deserialize_Transaction(data, transaction_index, owner_keys)
    if isinstance(data["hashBlock"], bytes):
        result = "block: " + b2hex(data["hashBlock"][::-1])
    if isinstance(data["merkleBranch"], bytes):
        result += f" {len(data['merkleBranch']) / 32} hashes in merkle branch\n"
    return result + tx


def parse_WalletTx(data_stream: BCDataStream) -> WalletTx:
    """Parse the wallet TX from"""
    # pylint: disable=unused-variable
    merkle: MerkleTx = parse_MerkleTx(data_stream)
    data: WalletTx = {}
    for k, val in merkle.items():
        data[k] = val  # type: ignore
    n_vtxPrev = data_stream.read_compact_size()
    data["vtxPrev"] = []
    for i in range(n_vtxPrev):
        data["vtxPrev"].append(parse_MerkleTx(data_stream))

    data["mapValue"] = {}
    n_mapValue = data_stream.read_compact_size()
    for i in range(n_mapValue):
        key = data_stream.read_string()
        value = data_stream.read_string()
        data["mapValue"][key] = value
    n_orderForm = data_stream.read_compact_size()
    data["orderForm"] = []
    for i in range(n_orderForm):
        first: bytes = data_stream.read_string()
        second: bytes = data_stream.read_string()
        data["orderForm"].append((first, second))
    data["fTimeReceivedIsTxTime"] = data_stream.read_uint32()
    data["timeReceived"] = data_stream.read_uint32()
    data["fromMe"] = data_stream.read_boolean()
    data["spent"] = data_stream.read_boolean()

    return data


def deserialize_WalletTx(
    data: WalletTx, transaction_index=None, owner_keys=None
) -> str:
    """Deserialize a wallet transaction from a Transaction dict to a str"""
    result = deserialize_MerkleTx(data, transaction_index, owner_keys)
    if isinstance(data["vtxPrev"], list):
        result += f"{len(data['vtxPrev'])} vtxPrev txns\n"
    result += "mapValue:" + str(data["mapValue"])
    if isinstance(data["orderForm"], bytes):
        if len(data["orderForm"]) > 0:
            result += "\n" + " orderForm:" + str(data["orderForm"])
    if isinstance(data["timeReceived"], int):
        result += "\n" + "timeReceived:" + time.ctime(data["timeReceived"])
    result += " fromMe:" + str(data["fromMe"]) + " spent:" + str(data["spent"])
    return result


def parse_AuxPow(data_stream: BCDataStream) -> Transaction:
    """The CAuxPow (auxiliary proof of work) structure supports merged mining.
    A flag in the block version field indicates the structure's presence.
    As of 8/2011, the Original Bitcoin Client does not use it.  CAuxPow
    originated in Namecoin; see
    https://github.com/vinced/namecoin/blob/mergedmine/doc/README_merged-mining.md.
    """
    data: Transaction = parse_MerkleTx(data_stream)
    n_chainMerkleBranch: int = data_stream.read_compact_size()
    data["chainMerkleBranch"] = data_stream.read_bytes(32 * n_chainMerkleBranch)
    data["chainIndex"] = data_stream.read_int32()
    data["parentBlock"] = parse_BlockHeader(data_stream)
    return data


def parse_BlockHeader(data_stream: BCDataStream) -> Block:
    """Parse the block header into a dict"""
    if data_stream.input is None:
        raise IOError
    data: Block = {}
    header_start = data_stream.read_cursor
    data["version"] = data_stream.read_int32()
    data["hashPrev"] = data_stream.read_bytes(32)
    data["hashMerkleRoot"] = data_stream.read_bytes(32)
    data["nTime"] = data_stream.read_uint32()
    data["nBits"] = data_stream.read_uint32()
    data["nNonce"] = data_stream.read_uint32()
    header_end = data_stream.read_cursor

    data["__header__"] = bytes(data_stream.input[header_start:header_end])
    return data


def parse_Block(data_stream: BCDataStream) -> Block:
    """Parse the block into a python dict"""
    data = parse_BlockHeader(data_stream)
    data["transactions"] = []
    nTransactions = data_stream.read_compact_size()
    if isinstance(data["transactions"], list):
        for _ in range(nTransactions):
            data["transactions"].append(parse_Transaction(data_stream))
    return data


def deserialize_Block(data: Block, print_raw_tx=False) -> str:
    """Deserialize the Block dict into a str"""
    result = "Time: " + time.ctime(data["nTime"]) + " Nonce: " + str(data["nNonce"])
    result += "\nnBits: 0x" + hex(data["nBits"])
    result += "\nhashMerkleRoot: 0x" + b2hex(data["hashMerkleRoot"][::-1])
    result += "\nPrevious block: " + b2hex(data["hashPrev"][::-1])
    if isinstance(data["transactions"], list):
        result += f"\n{len(data['transactions'])} transactions:\n"
        for txn in data["transactions"]:
            result += deserialize_Transaction(txn, print_raw_tx=print_raw_tx) + "\n"
    result += "\nRaw block header: " + b2hex(data["__header__"])
    return result


def parse_BlockLocator(data_stream: BCDataStream) -> Dict[str, List[bytes]]:
    """Parse the block locator

    Args:
        data_stream (BCDataStream): [description]

    Returns:
        Dict[str, List[bytes]]: [description]
    """
    # pylint: disable=unused-variable
    data: Dict[str, List[bytes]] = {"hashes": []}
    nHashes = data_stream.read_compact_size()
    for i in range(nHashes):
        data["hashes"].append(data_stream.read_bytes(32))
    return data


def deserialize_BlockLocator(data: Dict[str, List[bytes]]) -> str:
    """Deserialize the BlockLocator top from a dict to a str.

    Args:
        data (Dict[str, List[bytes]]): [description]

    Returns:
        str: [description]
    """
    return "Block Locator top: " + b2hex(data["hashes"][0][::-1])


def script_GetOp(
    script: bytes,
) -> Generator[Tuple[int, Optional[bytes]], None, None]:
    """From a script bytes retrieve the OP_CODES"""
    i = 0
    while i < len(script):
        vch: Union[bytes, None] = None
        opcode = int(script[i])
        i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                if i + 1 > len(script):
                    vch = None
                    i = len(script)
                else:
                    nSize = int(script[i])
                    i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                if i + 2 > len(script):
                    vch = None
                    i = len(script)
                else:
                    (nSize,) = struct.unpack_from(  # pylint: disable=no-member
                        "<H", script, i
                    )
                    i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                if i + 4 > len(script):
                    vch = None
                    i = len(script)
                else:
                    (nSize,) = struct.unpack_from(  # pylint: disable=no-member
                        "<I", script, i
                    )
                    i += 4
            if i + nSize > len(script):
                vch = None
                i = len(script)
            else:
                vch = script[i : i + nSize]
                i += nSize
        elif opcodes.OP_1 <= opcode <= opcodes.OP_16:
            vch = bytes(opcode - opcodes.OP_1 + 1)
        elif opcode == opcodes.OP_1NEGATE:
            vch = bytes(255)

        yield (opcode, vch)


def script_GetOpName(opcode: int) -> str:
    """Get the OP_CODE name

    Args:
        opcode (int): [description]

    Returns:
        str: [description]
    """
    try:
        return (opcodes.whatis(opcode)).replace("OP_", "")
    except KeyError:
        return "InvalidOp_" + str(opcode)


def decode_script(script: bytes) -> str:
    """Decode the Get OP script to a string

    Args:
        script (bytes): [description]

    Returns:
        str: [description]
    """
    result = ""
    for (opcode, vch) in script_GetOp(script):
        if len(result) > 0:
            result += " "
        if opcode <= opcodes.OP_PUSHDATA4 and isinstance(vch, bytes):
            result += f"{opcode}:"
            result += short_hex(vch)
        else:
            result += script_GetOpName(opcode)
    return result


def match_decoded(
    decoded: List[Tuple[int, Optional[bytes]]], to_match: List[int]
) -> bool:
    """Match the decoded OP codes to a match pattern

    Args:
        decoded (List[Tuple[int, Optional[bytes]]]): Decoded OP codes in script
        to_match (List[int]): Pattern to match the OP Codes to for specific transactions

    Returns:
        bool: [description]
    """
    if len(decoded) != len(to_match):
        return False
    for i, value in enumerate(decoded):
        if to_match[i] == opcodes.OP_PUSHDATA4 and value[0] <= opcodes.OP_PUSHDATA4:
            # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
            continue
        if to_match[i] != value[0]:
            return False
    return True


def extract_public_key(
    script: bytes, version: bytes = b"\x00"
) -> Union[Optional[bytes], List[Optional[bytes]]]:
    """Extract the pubkeys from the scriptPubKey"""
    try:
        decoded = list(script_GetOp(script))
    except struct.error:  # pylint: disable=no-member
        return None

    # non-generated Tx transactions push a signature
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
            return [
                public_key_to_bc_address(decoded[i][1])
                for i in range(1, len(decoded) - 1)
            ]

    # BIP16 TxOuts look like:
    # HASH160 20 BYTES:... EQUAL
    match = [opcodes.OP_HASH160, 0x14, opcodes.OP_EQUAL]
    if match_decoded(decoded, match):
        return hash_160_to_bc_address(decoded[1][1], version=b"\x05")

    return None
