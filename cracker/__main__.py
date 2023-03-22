import argparse
import timeit

from gesture import new_gesture_crack, old_gesture_crack
from password import new_password_crack, old_password_crack
from pin import new_pin_crack, old_pin_crack


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
    # print(old_gesture_crack(args.filename, args.length))  # Length is 5
    # print(new_gesture_crack(args.filename, args.length))  # Length is 4
    # print(old_password_crack(args.filename, args.wordlist, args.salt))  # Salt is 6343755648882345554
    # print(new_password_crack(args.filename, args.wordlist))
    # print(old_pin_crack(args.filename, args.length, args.salt))  # Length is 4, salt is 1059186646558953472
    print(new_pin_crack(args.filename, args.length))  # Length is 4


if __name__ == "__main__":
    start = timeit.default_timer()
    args = parse_args()
    print(timeit.default_timer() - start)
