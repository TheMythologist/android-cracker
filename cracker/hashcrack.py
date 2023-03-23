import hashlib
import multiprocessing

from CrackManager import CrackManager, HashParameter

FOUND = multiprocessing.Event()


class MD5Crack(CrackManager):
    def crack(self, params: HashParameter):
        to_hash = params.possible + params.salt
        hashed = hashlib.md5(to_hash).hexdigest().encode()
        if hashed == params.target:
            return params.possible.decode()


class ScryptCrack(CrackManager):
    def crack(self, params: HashParameter):
        to_hash = params.kwargs["meta"] + params.possible
        hashed = hashlib.scrypt(to_hash, salt=params.salt, n=16384, r=8, p=1, dklen=32)
        if hashed == params.target:
            return params.possible.decode()


class SHA1Crack(CrackManager):
    def crack(self, params: HashParameter):
        sha1 = hashlib.sha1(params.possible).hexdigest()
        if sha1 == params.target:
            return params.kwargs["original"]
