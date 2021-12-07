"""encode/decode base58 in the same way that Bitcoin does"""

from typing import Optional, Union
from base58 import b58encode, b58decode
from Crypto.Hash import SHA256, RIPEMD160
from util import hex2b, b2hex

# XXX This file only supports P2PKH and P2SH and neither Bech32 nor P2TR


def hash_160(public_key: Union[bytes, bytearray, memoryview, None]) -> bytes:
    """Conduct the Double hash of a public key using SHA256 first and then RIPEMD160"""
    hash_1 = SHA256.new(public_key).digest()
    hash_2 = RIPEMD160.new(hash_1).digest()
    return hash_2


def hash_160_to_bc_address(
    h160: Optional[bytes], version: bytes = b"\x00"
) -> Optional[bytes]:
    """Convert a hash160 into an address. The default address type is for Bitcoin"""
    if h160 is None:
        return None
    vh160 = version + h160
    hash_3 = SHA256.new(SHA256.new(vh160).digest()).digest()
    addr = vh160 + hash_3[0:4]
    return b58encode(addr)


def public_key_to_bc_address(
    public_key: Union[bytes, bytearray, memoryview, None], version: bytes = b"\x00"
) -> Optional[bytes]:
    """Generate the address from a public key. The default address type is for Bitcoin"""
    if public_key is None:
        return None
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, version)


def bc_address_to_hash_160(addr: bytes) -> bytes:
    """Convert an address into a hash160"""
    return b58decode(addr)


if __name__ == "__main__":
    X = hex2b("005cc87f4a3fdfe3a2346b6953267ca867282630d3f9b78e64")
    encoded = b58encode(X)
    print(encoded, b"19TbMSWwHvnxAKy12iNm3KdbGfzfaMFViT")
    print(b2hex(b58decode(encoded)), b2hex(X))
