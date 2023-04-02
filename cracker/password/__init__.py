import multiprocessing
import string
from io import BufferedReader, BytesIO
from typing import Iterable

from cracker.AbstractCracker import AbstractCracker
from cracker.CrackManager import CrackManager, run_crack
from cracker.exception import MissingArgumentException
from cracker.policy import DevicePolicy, PasswordProperty


class AbstractPasswordCracker(AbstractCracker):
    def __init__(
        self,
        file: BufferedReader,
        device_policy: DevicePolicy | None,
        wordlist_file: BufferedReader | None,
        cracker: type[CrackManager],
    ):
        if wordlist_file is None:
            raise MissingArgumentException("Wordlist argument is required")
        super().__init__(file, cracker)
        self.device_policy = device_policy
        self.wordlist_file = wordlist_file

    @staticmethod
    def get_password_property(password: bytes) -> PasswordProperty:
        upper = sum(char in string.ascii_uppercase.encode() for char in password)
        lower = sum(char in string.ascii_lowercase.encode() for char in password)
        numbers = sum(char in string.digits.encode() for char in password)
        symbols = sum(char in string.punctuation.encode() for char in password)
        return PasswordProperty(upper, lower, numbers, symbols)

    def run(self):
        queue = multiprocessing.Queue()
        found = multiprocessing.Event()
        result = multiprocessing.Queue()
        crackers = run_crack(self.cracker, queue, found, result)

        for word in self.parse_wordlist(self.wordlist_file):
            if self.device_policy is not None:
                if len(word) != self.device_policy.length:
                    continue
                if (
                    self.device_policy.filter is not None
                    and self.get_password_property(word) != self.device_policy.filter
                ):
                    continue
            if found.is_set():
                for cracker in crackers:
                    cracker.stop()
                break
            queue.put(self.generate_hashparameters(word))

        for cracker in crackers:
            cracker.join()
        queue.cancel_join_thread()
        print(f"Found key: {result.get()}")

    @staticmethod
    def parse_wordlist(wordlist: BytesIO) -> Iterable[bytes]:
        for word in wordlist:
            yield word.strip()
