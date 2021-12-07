"""Workalike python implementation of Bitcoin's CDataStream class."""
import struct
import mmap
from typing import Optional, Union
from Abe.exceptions import SerializationError


class BCDataStream:
    """Bitcoin's CDataStream Class"""

    def __init__(self):
        self.input: Union[bytes, bytearray, memoryview, None] = None
        self.read_cursor = int(0)

    def clear(self) -> None:
        """Reset cursor position"""
        self.input = None
        self.read_cursor = int(0)

    def write(self, _bytes: bytes) -> None:
        """Initialize with string of bytes"""
        if self.input is None:
            self.input = bytearray(_bytes)
        elif isinstance(self.input, bytearray):
            self.input += bytearray(_bytes)

    def map_file(self, file, start: int) -> None:
        """Initialize with bytes from file"""
        self.input = memoryview(mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ))
        self.read_cursor = start

    def seek_file(self, position: int) -> None:
        """Set the cursor position for the file"""
        self.read_cursor = position

    def close_file(self) -> None:
        """Close the file"""
        if isinstance(self.input, mmap.mmap):
            self.input.close()

    #
    # Read Methods
    #
    def read_string(self) -> bytes:
        """
        Strings are encoded depending on length:
            0 to 252 :  1-byte-length followed by bytes (if any)
            253 to 65,535 : byte'253' 2-byte-length followed by bytes
            65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
            ... and the Bitcoin client is coded to understand:
            greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
            ... but I don't think it actually handles any strings that big.
        """

        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        try:
            length = self.read_compact_size()
        except IndexError as error:
            raise SerializationError("attempt to read past end of buffer") from error

        return self.read_bytes(length)

    def read_bytes(self, length: int) -> bytes:
        """Read the bytes from the cursor position"""
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        try:
            result = self.input[self.read_cursor : self.read_cursor + length]
            self.read_cursor += length
            return result

        except IndexError as error:
            raise SerializationError("attempt to read past end of buffer") from error

    def read_marker(self) -> bytes:
        """Read the marker for BIP 141/144 transactions"""
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        return bytes(self.input[self.read_cursor : self.read_cursor + 1])

    def read_boolean(self) -> bool:
        """Read a boolean"""
        return self.read_bytes(1)[0] != b"\x00"

    def read_int16(self) -> int:
        """read_int16"""
        return self._read_num("<h")

    def read_uint16(self) -> int:
        """read_uint16"""
        return self._read_num("<H")

    def read_int32(self) -> int:
        """read_int32"""
        return self._read_num("<i")

    def read_uint32(self) -> int:
        """read_uint32"""
        return self._read_num("<I")

    def read_int64(self) -> int:
        """read_int64"""
        return self._read_num("<q")

    def read_uint64(self) -> int:
        """read_uint64"""
        return self._read_num("<Q")

    def read_compact_size(self) -> int:
        """Read the compact notation for integer compression"""
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")
        size = ord(bytes(self.input[self.read_cursor : self.read_cursor + 1]))
        self.read_cursor += 1
        if size == 253:
            size = self._read_num("<H")
        elif size == 254:
            size = self._read_num("<I")
        elif size == 255:
            size = self._read_num("<Q")
        return size

    def _read_num(self, _format: str) -> int:
        # pylint: disable=no-member

        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        num: int
        (num,) = struct.unpack_from(_format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(_format)
        return num

    #
    # Write Methods
    #
    # All of the write methods are Optional. The purpose is so that if they are passed None
    # the action is skipped. Thus when serializing data into raw bytes
    def write_string(self, string: Union[str, bytes, None]) -> None:
        """Length-encoded as with read_string"""
        if string is None:
            return None
        self.write_compact_size(len(string))
        if isinstance(string, str):
            self.write(bytes(string, "utf-8"))
        if isinstance(string, bytes):
            self.write(string)

    def write_boolean(self, val: Optional[int]) -> None:
        """write_boolean"""
        if val is None:
            return None
        self.write(b"\x01" if val else b"\x00")

    def write_int16(self, num: Optional[int]) -> None:
        """write_int16"""
        self._write_num("<h", num)

    def write_uint16(self, num: Optional[int]) -> None:
        """write_uint16"""
        self._write_num("<H", num)

    def write_int32(self, num: Optional[int]) -> None:
        """write_int32"""
        self._write_num("<i", num)

    def write_uint32(self, num: Optional[int]) -> None:
        """write_uint32"""
        self._write_num("<I", num)

    def write_int64(self, num: Optional[int]) -> None:
        """write_int64"""
        self._write_num("<q", num)

    def write_uint64(self, num: Optional[int]) -> None:
        """write_uint64"""
        self._write_num("<Q", num)

    def write_compact_size(self, size: Optional[int]) -> None:
        """Write an integer in its compressed form"""
        if size is None:
            return None
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        # specify the unsigned integer type
        if size < 253:
            pass
        elif size < 2 ** 16:
            self.write(b"\xfd")
        elif size < 2 ** 32:
            self.write(b"\xfe")
        elif size < 2 ** 64:
            self.write(b"\xff")
        # write the unsigned integer
        val = size.to_bytes((size.bit_length() + 7) // 8, "little")
        self.write(val)

    def _write_num(self, _format: str, num: Optional[int]) -> None:
        # pylint: disable=no-member
        if num is None:
            return None
        val = struct.pack(_format, num)
        self.write(val)
