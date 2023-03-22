from io import BufferedReader
import struct
from exception import InvalidFileException

from crack import crack, Parameter
from hash import new_pin_hash, old_pin_hash


def old_pin_crack(gesture_file: BufferedReader, length: int, salt: int):
    # Android versions <= 5.1
    gesture_file_contents = gesture_file.read()
    if len(gesture_file_contents) != 72:
        raise InvalidFileException("Gesture pattern file needs to be exactly 72 bytes")
    combined_hash = gesture_file_contents.decode().casefold()
    sha1, md5 = combined_hash[:40], combined_hash[40:]
    # Get salt
    salt1 = hex(salt & 0xFFFFFFFF)
    salt2 = hex(salt >> 32 & 0xFFFFFFFF)
    parsed_salt = salt2[2:] + salt1[2:]
    params = (
        Parameter(salt=parsed_salt, target=md5, possible=str(pos).zfill(length))
        for pos in range(10**length)
    )
    return crack(old_pin_hash, params)


def new_pin_crack(gesture_file: BufferedReader, length: int):
    # Android versions < 8.0, >= 6.0
    gesture_file_contents = gesture_file.read()
    if len(gesture_file_contents) != 58:
        raise InvalidFileException("Gesture pattern file needs to be exactly 58 bytes")
    s = struct.Struct("<17s 8s 32s")
    meta, salt, signature = s.unpack_from(gesture_file_contents)

    params = (
        Parameter(
            salt=salt,
            target=signature,
            possible=str(pos).zfill(length),
            kwargs={"meta": meta},
        )
        for pos in range(10**length)
    )
    return crack(new_pin_hash, params)
