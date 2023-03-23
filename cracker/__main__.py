import argparse
import timeit

from gesture import NewGestureCracker, OldGestureCracker
from password import NewPasswordCracker, OldPasswordCracker
from pin import NewPINCracker, OldPINCracker


def parse_args() -> None:
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
    crackers = {
        "pattern": {"new": NewGestureCracker, "old": OldGestureCracker},
        "password": {"new": NewPasswordCracker, "old": OldPasswordCracker},
        "pin": {"new": NewPINCracker, "old": OldPINCracker},
    }
    if 8 >= args.version >= 6:
        version = "new"
    elif args.version <= 5.1:
        version = "old"
    else:
        raise NotImplementedError(f"Too new android version: {args.version}")
    cracker = crackers[args.type][version]
    cracker(
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


if __name__ == "__main__":
    start = timeit.default_timer()
    args = parse_args()
    print(timeit.default_timer() - start)
