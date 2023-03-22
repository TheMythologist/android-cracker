import hashlib
import multiprocessing

from crack import Parameter

FOUND = multiprocessing.Event()


def old_pin_hash(params: Parameter):
    global FOUND
    if FOUND.is_set():
        return None
    to_hash = params.possible + params.salt
    hashed = hashlib.md5(to_hash).hexdigest()
    if hashed == params.target:
        FOUND.set()
        return params.possible
    return None


def scrypt_hash(params: Parameter):
    global FOUND
    if FOUND.is_set():
        return None
    to_hash = params.kwargs["meta"] + params.possible
    hashed = hashlib.scrypt(to_hash, salt=params.salt, n=16384, r=8, p=1, dklen=32)
    if hashed == params.target:
        FOUND.set()
        return params.possible.decode()
    return None
