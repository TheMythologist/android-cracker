import argparse
import logging
import timeit

from cracker.AbstractCracker import AbstractCracker
from cracker.gesture.crackers import NewGestureCracker, OldGestureCracker
from cracker.parsers.device_policies import retrieve_length
from cracker.parsers.locksettings import retrieve_salt
from cracker.password.crackers import NewPasswordCracker, OldPasswordCracker
from cracker.pin.crackers import NewPINCracker, OldPINCracker

log = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Crack some Android devices!")
    parser.add_argument(
        "filename", type=argparse.FileType("rb"), help="File for cracking"
    )
    parser.add_argument(
        "-av", "--version", required=True, type=float, help="Android version (e.g. 5.1)"
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
    information = parser.add_mutually_exclusive_group()
    information.add_argument(
        "-p",
        "--policy",
        type=argparse.FileType(),
        help="File path to device_policies.xml",
    )
    information.add_argument(
        "-l", "--length", type=int, help="Length of the pattern/password/pin"
    )
    salt = parser.add_mutually_exclusive_group()
    salt.add_argument(
        "-s",
        "--salt",
        type=int,
        help="Salt, only used in cracking passwords and PINs for Android versions <= 5.1",
    )
    salt.add_argument(
        "-D",
        "--database",
        type=argparse.FileType(),
        help="File path to locksettings.db",
    )
    parser.add_argument(
        "--log",
        default="warning",
        choices=[level.lower() for level in logging._nameToLevel.keys()],
        type=str.lower,
        help="Provide logging level. Example --loglevel debug, default=warning",
    )
    args = parser.parse_args()
    logging.basicConfig(level=args.log.upper())

    if args.wordlist and args.type != "password":
        logging.warning(
            'Wordlist specified but password type is not "password", ignoring'
        )

    if 8 >= args.version >= 6:
        args.version = "new"
    elif args.version <= 5.1:
        args.version = "old"
    else:
        raise NotImplementedError(f"Too new android version: {args.version}")

    if args.salt is not None:
        args.salt &= 0xFFFFFFFFFFFFFFFF
    if args.database is not None:
        args.salt = retrieve_salt(args.database.name)
        log.info("Retrieved salt %d", args.salt)

    if args.policy is not None:
        args.length = retrieve_length(args.policy.read())
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


def run() -> None:
    args = parse_args()
    print("Starting crack...")
    start = timeit.default_timer()
    begin_crack(args)
    print(f"Time taken: {timeit.default_timer() - start:.3f}s")


if __name__ == "__main__":
    run()
