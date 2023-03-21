import hashlib
from io import BufferedReader
import struct

from exception import InvalidFileException
from wordlist import parse_wordlist


def old_password_crack(gesture_file: BufferedReader, wordlist_file: BufferedReader, salt: int):
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

    for word in parse_wordlist(wordlist_file):
        salted = word + parsed_salt.encode()
        hashed = hashlib.md5(salted).hexdigest()
        if hashed == md5:
            return word


def new_password_crack(gesture_file: BufferedReader, wordlist_file: BufferedReader):
    # Android versions < 8.0, >= 6.0
    N = 16384
    r = 8
    p = 1
    gesture_file_contents = gesture_file.read()
    if len(gesture_file_contents) != 58:
        raise InvalidFileException("Gesture pattern file needs to be exactly 58 bytes")
    s = struct.Struct("<17s 8s 32s")
    meta, salt, signature = s.unpack_from(gesture_file_contents)
    for word in parse_wordlist(wordlist_file):
        to_hash = meta + word
        hashed = hashlib.scrypt(to_hash, salt=salt, n=N, r=r, p=p)
        if hashed[:32] == signature:
            return word
