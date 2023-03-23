import binascii
import hashlib
import multiprocessing
import struct
from io import BufferedReader
from itertools import permutations
from string import digits

from AbstractCracker import AbstractCracker
from CrackManager import CrackManager, HashParameter, run_crack
from exception import InvalidFileException
from hashcrack import ScryptCrack, SHA1Crack


class AbstractGestureCracker(AbstractCracker):
    def __init__(self, file: BufferedReader, length: int, cracker: CrackManager):
        super().__init__(file, cracker)
        self.length = length

    def run(self):
        queue = multiprocessing.Queue()
        found = multiprocessing.Event()
        crackers = run_crack(self.cracker, queue, found)

        for possible_num in permutations(digits, self.length):
            if found.is_set():
                for cracker in crackers:
                    cracker.stop()
                break
            queue.put(self.generate_hashparameters("".join(possible_num)))

        for cracker in crackers:
            cracker.join()
        queue.cancel_join_thread()


class OldGestureCracker(AbstractGestureCracker):
    # Android versions <= 5.1

    def __init__(self, file: BufferedReader, length: int, **kwargs):
        super().__init__(file, length, SHA1Crack)
        self.target = self.file_contents.hex()

    def validate(self):
        if len(self.file_contents) != hashlib.sha1().digest_size:
            raise InvalidFileException(
                "Gesture pattern file needs to be exactly 20 bytes"
            )

    def generate_hashparameters(self, possible_pin: str) -> HashParameter:
        key = binascii.unhexlify(
            "".join(f"{ord(c) - ord('0'):02x}" for c in possible_pin)
        )
        return HashParameter(
            target=self.target, possible=key, kwargs={"original": possible_pin}
        )


class NewGestureCracker(AbstractGestureCracker):
    # Android versions < 8.0, >= 6.0

    def __init__(self, file: BufferedReader, length: int, **kwargs):
        super().__init__(file, length, ScryptCrack)
        s = struct.Struct("<17s 8s 32s")
        self.meta, self.salt, self.signature = s.unpack_from(self.file_contents)

    def validate(self):
        if len(self.file_contents) != 58:
            raise InvalidFileException(
                "Gesture pattern file needs to be exactly 58 bytes"
            )

    def generate_hashparameters(self, possible_pin: str) -> HashParameter:
        return HashParameter(
            salt=self.salt,
            target=self.signature,
            possible=possible_pin.encode(),
            kwargs={"meta": self.meta},
        )
