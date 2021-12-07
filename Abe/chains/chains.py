"""Library that contains all of the chain specific information"""

from typing import Union
from Abe import util, deserialize
from Abe.streams import BCDataStream
from Abe.typing import Block, Transaction, opcodes
from .base_chain import BaseChain, SCRIPT_TYPE_UNKNOWN

try:
    import ltc_scrypt

except ImportError:
    ltc_scrypt = None

try:
    import xcoin_hash
except ImportError:
    xcoin_hash = None

__all__ = [
    "Sha256Chain",
    "Bitcoin",
    "Testnet",
    "Californium",
    "LegacyNoBit8",
    "Unbreakablecoin",
    "LtcScryptChain",
    "KeccakChain",
    "Maxcoin",
    "X11Chain",
    "Dash",
    "Hirocoin",
    "NmcAuxPowChain",
    "Sha256NmcAuxPowChain",
    "Namecoin",
    "PpcPosChain",
    "X11PosChain",
    "NvcChain",
    "CryptoCash",
    "NovaCoin",
    "BlackCoin",
]
###############################################
# SHA256 Based Coins
###############################################
class Sha256Chain(BaseChain):
    """
    A blockchain that hashes its block headers using double SHA2-256 as Bitcoin does.
    """

    def __init__(self, src=None, **kwargs):
        super().__init__(src, **kwargs)


class Bitcoin(Sha256Chain):
    """
    The bitcoin blockchain.
    """

    def __init__(self, src=None, **kwargs):
        super().__init__(src, **kwargs)
        self.name: str = "Bitcoin"
        self.code3: str = "BTC"
        self.address_version: bytes = b"\x00"
        self.script_addr_vers: bytes = b"\x05"
        self.magic: bytes = b"\xf9\xbe\xb4\xd9"


class Testnet(Sha256Chain):
    """
    The original bitcoin test blockchain.
    """

    def __init__(self, src=None, **kwargs):
        self.name: str = "Testnet"
        self.code3: str = "BC0"
        self.address_version: bytes = b"\x6f"
        self.script_addr_vers: bytes = b"\xc4"
        self.magic: bytes = b"\xfa\xbf\xb5\xda"
        self.datadir_rpcport: int = 18332
        super().__init__(src, **kwargs)


class Californium(Sha256Chain):
    """Californium"""

    def __init__(self, src=None, **kwargs):
        self.name: str = "Californium"
        # FIX make it 'CF'
        self.code3: str = "CF "
        self.address_version: bytes = b"\x58"
        self.script_addr_vers: bytes = b"\x1E"
        self.magic: bytes = b"\x0f\xdb\xbb\x07"
        self.datadir_conf_file_name: str = "Californium.conf"
        self.datadir_rpcport: int = 44254
        self.datadir_p2pport: int = 44252
        super().__init__(src, **kwargs)


class LegacyNoBit8(Sha256Chain):
    """
    Same as Sha256Chain, for backwards compatibility.
    """


class Unbreakablecoin(Sha256Chain):
    """Unbreakablecoin"""

    def __init__(self, src=None, **kwargs):
        self.name: str = "Unbreakablecoin"
        self.code3: str = "UNB"
        self.address_version: bytes = b"\x00"
        self.script_addr_vers: bytes = b"\x05"
        self.magic: bytes = b"\x83\x33\x07\xb1"
        self.datadir_conf_file_name: str = "Unbreakablecoin.conf"
        self.datadir_rpcport: int = 9337
        self.datadir_p2pport: int = 9336
        super().__init__(src, **kwargs)


###########################################
# LTC Scrypt Coins
###########################################
class LtcScryptChain(BaseChain):
    """
    A blockchain using Litecoin's scrypt algorithm to hash block headers.
    """

    def __init__(self, src=None, **kwargs):
        super().__init__(src, **kwargs)

    def block_header_hash(
        self, header: Union[bytes, bytearray, memoryview, None]
    ) -> bytes:
        return ltc_scrypt.getPoWHash(header)  # type: ignore


###############################################
# KeccakChain Based Coins
###############################################
class KeccakChain(BaseChain):
    """
    A blockchain using 256-bit SHA3 (Keccak) as the block header hash.
    """

    def __init__(self, src=None, **kwargs):
        super().__init__(src, **kwargs)

    def block_header_hash(
        self, header: Union[bytes, bytearray, memoryview, None]
    ) -> bytes:
        return util.sha3_256(header)


class Maxcoin(KeccakChain):
    """
    Maxcoin uses Keccak for block headers and single SHA-256 for transactions.
    """

    def __init__(self, src=None, **kwargs):
        self.name: str = "Maxcoin"
        self.code3: str = "MAX"
        self.address_version: bytes = b"\x6e"
        self.script_addr_vers: bytes = b"\x70"
        self.magic: bytes = b"\xf9\xbe\xbb\xd2"
        self.datadir_conf_file_name: str = "maxcoin.conf"
        self.datadir_rpcport: int = 8669
        super().__init__(src, **kwargs)

    def transaction_hash(self, transaction: bytes) -> bytes:
        return util.sha256(transaction)


###############################################
# X11 Based Chains
###############################################
class X11Chain(BaseChain):
    """
    A blockchain that hashes block headers using the X11 algorithm.
    The current implementation requires the xcoin_hash module.
    """

    def __init__(self, src=None, **kwargs):
        super().__init__(src, **kwargs)

    def block_header_hash(
        self, header: Union[bytes, bytearray, memoryview, None]
    ) -> bytes:
        return xcoin_hash.getPoWHash(header)  # type: ignore


class Dash(X11Chain):
    """Dash"""

    def __init__(self, src=None, **kwargs):
        self.name: str = "Dash"
        self.code3: str = "DASH"
        self.address_version: bytes = b"\x4c"
        self.script_addr_vers: bytes = b"\x05"
        self.magic: bytes = b"\xbf\x0c\x6b\xbd"
        self.datadir_conf_file_name: str = "dash.conf"
        self.datadir_rpcport: int = 9998
        self.datadir_p2pport: int = 9999
        super().__init__(src, **kwargs)


class Hirocoin(X11Chain):
    """Hirocoin"""

    def __init__(self, src=None, **kwargs):
        self.name: str = "Hirocoin"
        self.code3: str = "HIRO"
        self.address_version: bytes = b"\x28"
        self.script_addr_vers: bytes = b"\x05"
        self.magic: bytes = b"\xfe\xc4\xb9\xde"
        self.datadir_conf_file_name: str = "hirocoin.conf"
        self.datadir_rpcport: int = 9347
        self.datadir_p2pport: int = 9348
        super().__init__(src, **kwargs)


###########################################
# Aux PoW Coins
###########################################
class NmcAuxPowChain(BaseChain):
    """
    A blockchain that represents merge-mining proof-of-work in an "AuxPow" structure as does
    Namecoin.
    """

    def __init__(self, src=None, **kwargs):
        super().__init__(src, **kwargs)

    def ds_parse_block_header(self, data_stream: BCDataStream) -> Block:
        block_header: Block = BaseChain.ds_parse_block_header(self, data_stream)
        if block_header["version"] & (1 << 8):
            block_header["auxpow"] = deserialize.parse_AuxPow(data_stream)
        return block_header

    def has_feature(self, feature: str):
        return feature == "block_version_bit8_merge_mine"


class Sha256NmcAuxPowChain(Sha256Chain, NmcAuxPowChain):
    """Sha256NmcAuxPowChain"""


class Namecoin(Sha256NmcAuxPowChain):
    """
    Namecoin represents name operations in transaction output scripts.
    """

    def __init__(self, src=None, **kwargs):
        self.name: str = "Namecoin"
        self.code3: str = "NMC"
        self.address_version: bytes = b"\x34"
        self.magic: bytes = b"\xf9\xbe\xb4\xfe"
        super().__init__(src, **kwargs)

    _drops = (opcodes.OP_NOP, opcodes.OP_DROP, opcodes.OP_2DROP)

    def parse_decoded_txout_script(self, decoded):
        start = 0
        pushed = 0

        # Tolerate (but ignore for now) name operations.
        for i, value in enumerate(decoded):
            opcode = value[0]

            if (
                value[1] is not None
                or opcode == opcodes.OP_0
                or opcode == opcodes.OP_1NEGATE
                or opcodes.OP_1 <= opcode <= opcodes.OP_16
            ):
                pushed += 1
            elif opcode in self._drops:
                to_drop = self._drops.index(opcode)
                if pushed < to_drop:
                    break
                pushed -= to_drop
                start = i + 1
            else:
                return Sha256NmcAuxPowChain.parse_decoded_txout_script(
                    self, value[start:]
                )

        return SCRIPT_TYPE_UNKNOWN, decoded

    datadir_conf_file_name = "namecoin.conf"
    datadir_rpcport = 8336


###########################################
# Proof of Stake Coins
###########################################
class PpcPosChain(BaseChain):
    """
    A blockchain with proof-of-stake as in Peercoin.
    """

    def __init__(self, src=None, **kwargs):
        super().__init__(src, **kwargs)

    def ds_parse_transaction(self, data_stream: BCDataStream) -> Transaction:
        return deserialize.parse_Transaction(data_stream, has_nTime=True)  # type: ignore

    def ds_parse_block(self, data_stream: BCDataStream) -> Block:
        block: Block = BaseChain.ds_parse_block(self, data_stream)  # type: ignore
        block["block_sig"] = data_stream.read_bytes(data_stream.read_compact_size())
        return block


class X11PosChain(X11Chain, PpcPosChain):
    """A Proof of work X11Chain"""

    def __init__(self, src=None, **kwargs):
        X11Chain.__init__(self, src, **kwargs)
        PpcPosChain.__init__(self, src, **kwargs)


###########################################
# NovaCoin based PoS
###########################################


class NvcChain(LtcScryptChain, PpcPosChain):
    """
    Chain with NovaCoin-style proof of stake.
    """

    def __init__(self, src=None, **kwargs):
        PpcPosChain.__init__(self, src, **kwargs)
        LtcScryptChain.__init__(self, src, **kwargs)

    def has_feature(self, feature: str):
        return feature == "nvc_proof_of_stake"


class CryptoCash(NvcChain):
    """CryptoCash"""

    def __init__(self, src=None, **kwargs):
        self.name: str = "Cash"
        self.code3: str = "CAS"
        self.address_version: bytes = b"\x22"
        self.magic: bytes = b"\xe4\xc6\xfe\xe7"
        self.datadir_conf_file_name: str = "Cash.conf"
        self.datadir_rpcport: int = 3941
        super().__init__(src, **kwargs)


class NovaCoin(NvcChain):
    """NovaCoin"""

    def __init__(self, src=None, **kwargs):
        self.name: str = "NovaCoin"
        self.code3: str = "NVC"
        self.address_version: bytes = b"\x08"
        self.magic: bytes = b"\xe4\xe8\xe9\xe5"
        self.decimals = 6
        self.datadir_conf_file_name: str = "novacoin.conf"
        self.datadir_rpcport: int = 8344
        super().__init__(src, **kwargs)


class BlackCoin(NvcChain):
    """BlackCoin"""

    def __init__(self, src=None, **kwargs):
        self.name: str = "BlackCoin"
        self.code3: str = "BLK"
        self.address_version: bytes = b"\x19"
        self.script_addr_vers: bytes = b"\x55"
        self.magic: bytes = b"\x70\x35\x22\x05"
        self.datadir_conf_file_name: str = "blackcoin.conf"
        self.datadir_rpcport: int = 15715
        super().__init__(src, **kwargs)

    def ds_block_header_hash(self, data_stream: BCDataStream) -> bytes:
        block: Block = BaseChain.ds_parse_block_header(self, data_stream)
        if block["version"] > 6:
            return util.double_sha256(block["__header__"])
        return ltc_scrypt.getPoWHash(block["__header__"])  # type: ignore
