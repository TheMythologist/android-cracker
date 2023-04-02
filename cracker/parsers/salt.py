import struct


def old_extract_salt(salt: int) -> bytes:
    salt1 = hex(salt & 0xFFFFFFFF)
    salt2 = hex(salt >> 32 & 0xFFFFFFFF)
    return (salt2[2:] + salt1[2:]).encode()


def new_extract_info(contents: bytes) -> tuple[bytes, bytes, bytes]:
    s = struct.Struct("<17s 8s 32s")
    return s.unpack_from(contents)  # type: ignore[return-value]
