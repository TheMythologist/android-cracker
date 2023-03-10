from dataclasses import dataclass
import sys
import timeit
import multiprocessing
import hashlib
import itertools
from pathlib import Path

PIN_MAX = 4
PASSWD_MAX = 4
FOUND = multiprocessing.Event()


@dataclass
class Parameter:
    lenhash: int
    target: bytes
    salt: str
    positions: list[str]


def lookup(params: Parameter) -> str | None:
    global FOUND

    if FOUND.is_set() is True:
        return None

    perms = itertools.permutations(params.positions, params.lenhash)
    for item in perms:
        if FOUND.is_set() is True:
            return None
        passwd = "".join(str(v) for v in item)
        salted = passwd + params.salt
        sha1 = hashlib.sha1(salted.encode()).hexdigest()
        md5 = hashlib.md5(salted.encode()).hexdigest()
        digest = sha1 + md5
        if digest.upper().encode() == params.target:
            FOUND.set()
            return passwd
    return None


def crack(target_hash: bytes, salt: str) -> str | None:
    return crack_pin(target_hash, salt) or crack_password(target_hash, salt)


def crack_pin(target_hash: bytes, salt: str) -> str | None:
    ncores = multiprocessing.cpu_count()

    # First try pin
    positions = list("0123456789")
    pool = multiprocessing.Pool(ncores)
    params = [
        Parameter(count, target_hash, salt, positions)
        for count, _ in enumerate(range(PIN_MAX), start=1)
    ]
    result = pool.map(lookup, params)
    pool.close()
    pool.join()

    return next((r for r in result if r is not None), None)


def crack_password(target_hash: bytes, salt: str) -> str | None:
    ncores = multiprocessing.cpu_count()
    # Then try passwd
    positions = list("0123456789abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ")
    pool = multiprocessing.Pool(ncores)
    params = [
        Parameter(count, target_hash, salt, positions)
        for count, _ in enumerate(range(PASSWD_MAX), start=1)
    ]
    result = pool.map(lookup, params)
    pool.close()
    pool.join()

    return next((r for r in result if r is not None), None)


def crack_password_wordlist(target_hash: bytes, salt: str, wordlist_path: str) -> str | None:
    global FOUND
    with open(wordlist_path, "rb") as f:
        words = [word.strip() for word in f.readlines()]
    for word in words:
        salted = word + salt.encode()
        sha1 = hashlib.sha1(salted).hexdigest()
        md5 = hashlib.md5(salted).hexdigest()
        digest = sha1 + md5
        if digest.upper().encode() == target_hash:
            FOUND.set()
            return word.decode()
    return None


def main() -> None:
    # Check parameters
    if len(sys.argv) != 3:
        print(f"[+] Usage: {sys.argv[0]} /path/to/password.key salt")
        sys.exit(0)

    password_key_path = Path(sys.argv[1])
    hashLen = hashlib.sha1().digest_size + hashlib.md5().digest_size

    # Check password.key file
    if password_key_path.exists():
        if password_key_path.stat().st_size != hashLen * 2:
            print("[+] Invalid passwd file")
            sys.exit(-2)
    else:
        print(f"[+] Cannot access to {sys.argv[1]} file")
        sys.exit(-1)

    # Load digest from file
    digest = password_key_path.read_bytes()

    # Get salt
    salt1 = hex(int(sys.argv[2]) & 0xFFFFFFFF)
    salt2 = hex(int(sys.argv[2]) >> 32 & 0xFFFFFFFF)
    salt = salt2[2:] + salt1[2:]

    # Try to crack the passwd
    t0 = timeit.default_timer()
    # passwd = crack(digest, salt)
    passwd = crack_password_wordlist(digest, salt, r"C:\Users\KaiXuan\Documents\DO NOT DELETE\cracking\rockyou.txt")
    time_taken = timeit.default_timer() - t0

    if passwd is None:
        print("[:(] The password was not found...")
    else:
        print(f"[:D] The password has been FOUND!! => {passwd}")
    print(f"It took: {time_taken:.4f} seconds")

    sys.exit(0)


if __name__ == "__main__":
    main()
