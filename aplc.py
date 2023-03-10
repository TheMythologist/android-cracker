import sys
import timeit
import multiprocessing
import hashlib
import binascii
import itertools
from pathlib import Path
from dataclasses import dataclass

MATRIX_SIZE = [3, 3]
MAX_LEN = MATRIX_SIZE[0] * MATRIX_SIZE[1]
MIN_POSITIONS_NUMBER = 3
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


def show_pattern(pattern: str) -> None:
    """
    Shows the pattern "graphically"
    """

    gesture: list[int | None] = [None, None, None, None, None, None, None, None, None]

    for index, num in enumerate(pattern, start=1):
        gesture[int(num)] = index
    print("[+] Gesture:")
    for number in range(3):
        val: list[str | None] = [None, None, None]
        for j in range(3):
            val[j] = " " if gesture[number * 3 + j] is None else str(gesture[number * 3 + j])

        print("  -----  -----  -----")
        print(f"  | {val[0]} |  | {val[1]} |  | {val[2]} |  ")
        print("  -----  -----  -----")


def crack(target_hash: str) -> str | None:
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


def main() -> None:
    # check parameters
    if len(sys.argv) != 2:
        print(f"[+] Usage: {sys.argv[0]} /path/to/gesture.key")
        sys.exit(0)

    gesture_key_path = Path(sys.argv[1])

    # check gesture.key file
    if gesture_key_path.exists():
        if gesture_key_path.stat().st_size != hashlib.sha1().digest_size:
            print("[e] Invalid gesture file")
            sys.exit(-2)
    else:
        print(f"[e] Cannot access {sys.argv[1]} file")
        sys.exit(-1)

    # load SHA1 hash from file
    gest = gesture_key_path.read_bytes().hex()

    # try to crack the pattern
    t0 = timeit.default_timer()
    pattern = crack(gest)
    time_taken = timeit.default_timer() - t0

    if pattern is None:
        print("[:(] The pattern was not found...")
        rcode = -1
    else:
        print(f"[:D] The pattern has been FOUND!!! => {pattern}")
        show_pattern(pattern)
        print("")
        print(f"It took: {time_taken:.4f} seconds")
        rcode = 0

    sys.exit(rcode)


if __name__ == "__main__":
    main()
