import binascii
import hashlib
import struct
from io import BufferedReader
from itertools import permutations
from string import digits

from exception import InvalidFileException


def old_gesture_crack(gesture_file: BufferedReader, gesture_length: int):
    # Android versions <= 5.1
    gesture_file_contents = gesture_file.read()
    if len(gesture_file_contents) != hashlib.sha1().digest_size:
        raise InvalidFileException("Gesture pattern file needs to be exactly 20 bytes")
    target = gesture_file_contents.hex()
    for possible_num in permutations(digits, gesture_length):
        num = "".join(possible_num)
        key = binascii.unhexlify("".join(f"{ord(c) - ord('0'):02x}" for c in num))
        sha1 = hashlib.sha1(key).hexdigest()
        if sha1 == target:
            return num


def new_gesture_crack(gesture_file: BufferedReader, gesture_length: int):
    # Android versions < 8.0, >= 6.0
    N = 16384
    r = 8
    p = 1
    gesture_file_contents = gesture_file.read()
    if len(gesture_file_contents) != 58:
        raise InvalidFileException("Gesture pattern file needs to be exactly 58 bytes")
    s = struct.Struct("<17s 8s 32s")
    meta, salt, signature = s.unpack_from(gesture_file_contents)
    for possible_num in range(10**gesture_length):
        num = str(possible_num).zfill(gesture_length)
        if len(set(num)) != len(num):
            continue
        to_hash = meta + num.encode()
        hashed = hashlib.scrypt(to_hash, salt=salt, n=N, r=r, p=p, dklen=32)
        if hashed == signature:
            return possible_num
