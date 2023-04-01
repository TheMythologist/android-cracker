import argparse
import timeit

from cracker.AbstractCracker import AbstractCracker
from cracker.gesture.crackers import NewGestureCracker, OldGestureCracker
from cracker.password.crackers import NewPasswordCracker, OldPasswordCracker
from cracker.pin.crackers import NewPINCracker, OldPINCracker


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Crack some Android devices!")
    parser.add_argument(
        "filename", type=argparse.FileType("rb"), help="File for cracking"
    )
    parser.add_argument(
        "-v", "--version", required=True, type=float, help="Android version (e.g. 5.1)"
    )
    parser.add_argument(
        "-t",
        "--type",
        required=True,
        type=str.casefold,
        choices=("pattern", "password", "pin"),
        help="Type of password to crack",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help="Wordlist to use for cracking",
        type=argparse.FileType("rb"),
    )
    parser.add_argument(
        "-p",
        "--policy",
        type=argparse.FileType(),
        help="File path to device_policies.xml",
    )
    parser.add_argument(
        "-l", "--length", type=int, help="Length of the pattern/password/pin"
    )
    parser.add_argument(
        "-s",
        "--salt",
        type=int,
        help="Salt, only used in cracking passwords and PINs for Android versions <= 5.1",
    )
    parser.add_argument(
        "-D",
        "--database",
        type=argparse.FileType(),
        help="File path to locksettings.db",
    )
    args = parser.parse_args()
    if args.wordlist and args.type != "password":
        print("Wordlist specified but password type is not 'password', ignoring")
    if 8 >= args.version >= 6:
        args.version = "new"
    elif args.version <= 5.1:
        args.version = "old"
    else:
        raise NotImplementedError(f"Too new android version: {args.version}")
    return args


def begin_crack(args: argparse.Namespace) -> None:
    crackers: dict[str, dict[str, type[AbstractCracker]]] = {
        "pattern": {"new": NewGestureCracker, "old": OldGestureCracker},
        "password": {"new": NewPasswordCracker, "old": OldPasswordCracker},
        "pin": {"new": NewPINCracker, "old": OldPINCracker},
    }
    cracker = crackers[args.type][args.version]
    cracker(  # type: ignore[call-arg]
        file=args.filename,
        length=args.length,
        salt=args.salt,
        wordlist_file=args.wordlist,
    ).run()
    # OldGestureCracker(args.filename, args.length).run()  # Length is 5
    # NewGestureCracker(args.filename, args.length).run()  # Length is 4
    # OldPasswordCracker(args.filename, args.wordlist, args.salt).run()  # Salt is 6343755648882345554
    # NewPasswordCracker(args.filename, args.wordlist).run()
    # OldPINCracker(args.filename, args.length, args.salt).run()  # Length is 4, salt is 1059186646558953472
    # NewPINCracker(args.filename, args.length).run()  # Length is 4


def run() -> None:
    start = timeit.default_timer()
    args = parse_args()
    begin_crack(args)
    print(f"Time taken: {timeit.default_timer() - start:.3f}s")


if __name__ == "__main__":
    run()
