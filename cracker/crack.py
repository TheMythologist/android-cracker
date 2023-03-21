import binascii
from dataclasses import dataclass
import hashlib
import itertools
import multiprocessing

FOUND = multiprocessing.Event()


@dataclass
class Parameter:
    lenhash: int
    target: str
    positions: list[int]


def lookup(param: Parameter) -> str | None:
    global FOUND

    if FOUND.is_set():
        return None

    # get all possible permutations
    perms = itertools.permutations(param.positions, param.lenhash)
    # for each permutation
    for item in perms:
        # build the pattern string
        if FOUND.is_set():
            return None
        pattern = "".join(str(v) for v in item)
        # convert the pattern to hex (so the string '123' becomes '\x01\x02\x03')
        key = binascii.unhexlify("".join(f"{(ord(c) - ord('0')):02x}" for c in pattern))
        # compute the hash for that key
        sha1 = hashlib.sha1(key).hexdigest()
        # pattern found
        if sha1 == param.target:
            FOUND.set()
            return pattern
    # pattern not found
    return None


def crack(target_hash: str, possible) -> str | None:
    ncores = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(ncores)
    # generates the matrix positions IDs
    positions = list(range(MAX_LEN))

    # sets the length for each worker
    def generate_worker_params(x: int) -> Parameter:
        return Parameter(x, target_hash, positions)

    params = [
        generate_worker_params(i) for i in range(MIN_POSITIONS_NUMBER, MAX_LEN + 1)
    ]

    result = pool.map(lookup, params)
    pool.close()
    pool.join()

    return next((r for r in result if r is not None), None)
