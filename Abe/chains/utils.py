"""Utility tools to use with Chains"""
from typing import Union
from Abe.streams import BCDataStream
from Abe.typing import Transaction, Block, TxIn, TxOut


def ds_serialize_block_header(data_stream: BCDataStream, block: Block) -> None:
    """ds_serialize_block_header"""
    data_stream.write_int32(block["version"])
    data_stream.write(block["hashPrev"])
    data_stream.write(block["hashMerkleRoot"])
    data_stream.write_uint32(block["nTime"])
    data_stream.write_uint32(block["nBits"])
    data_stream.write_uint32(block["nNonce"])


def ds_serialize_transaction(
    data_stream: BCDataStream, transaction: Transaction
) -> None:
    """ds_serialize_transaction"""
    data_stream.write_int32(transaction["version"])
    data_stream.write_compact_size(len(transaction["txIn"]))
    for txin in transaction["txIn"]:
        ds_serialize_txin(data_stream, txin)
    data_stream.write_compact_size(len(transaction["txOut"]))
    for txout in transaction["txOut"]:
        ds_serialize_txout(data_stream, txout)
    data_stream.write_uint32(transaction["lockTime"])


def ds_serialize_block(data_stream: BCDataStream, block: Block) -> None:
    """ds_serialize_block"""
    ds_serialize_block_header(data_stream, block)
    data_stream.write_compact_size(len(block["transactions"]))
    for transaction in block["transactions"]:
        ds_serialize_transaction(data_stream, transaction)


def ds_serialize_txin(data_stream: BCDataStream, txin: TxIn) -> None:
    """ds_serialize_txin"""
    data_stream.write(txin["prevout_hash"])
    data_stream.write_uint32(txin["prevout_n"])
    data_stream.write_string(txin["scriptSig"])
    data_stream.write_uint32(txin["sequence"])


def ds_serialize_txout(data_stream: BCDataStream, txout: TxOut) -> None:
    """ds_serialize_txout"""
    data_stream.write_int64(txout["value"])
    data_stream.write_string(txout["scriptPubKey"])


def serialize_block(block: Block) -> Union[bytearray, memoryview, None]:
    """serialize_block"""
    data_stream = BCDataStream()
    ds_serialize_block(data_stream, block)
    return data_stream.input


def serialize_block_header(block: Block) -> Union[bytearray, memoryview, None]:
    """serialize_block_header"""
    data_stream = BCDataStream()
    ds_serialize_block_header(data_stream, block)
    return data_stream.input


def serialize_transaction(
    transaction: Transaction,
) -> Union[bytearray, memoryview, None]:
    """serialize_transaction"""
    data_stream = BCDataStream()
    ds_serialize_transaction(data_stream, transaction)
    return data_stream.input
