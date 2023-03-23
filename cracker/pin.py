import multiprocessing
import struct
from io import BufferedReader

from AbstractCracker import AbstractCracker
from CrackManager import CrackManager, HashParameter, run_crack
from exception import InvalidFileException
from hashcrack import MD5Crack, ScryptCrack


class AbstractPINCracker(AbstractCracker):
    def __init__(
        self, file: BufferedReader, length: int, cracker: CrackManager
    ):
        super().__init__(file, cracker)
        self.length = length

    def run(self):
        queue = multiprocessing.Queue()
        found = multiprocessing.Event()
        crackers = run_crack(self.cracker, queue, found)

        for possible_pin in range(10**self.length):
            if found.is_set():
                for cracker in crackers:
                    cracker.stop()
                break
            queue.put(self.generate_hashparameters(possible_pin))

        for cracker in crackers:
            cracker.join()
        queue.cancel_join_thread()


class OldPINCracker(AbstractPINCracker):
    # Android versions <= 5.1

    def __init__(self, file: BufferedReader, length: int, salt: int, **kwargs):
        super().__init__(file, length, MD5Crack)
        combined_hash = self.file_contents.lower()
        sha1, md5 = combined_hash[:40], combined_hash[40:]
        salt1 = hex(salt & 0xFFFFFFFF)
        salt2 = hex(salt >> 32 & 0xFFFFFFFF)
        self.salt = (salt2[2:] + salt1[2:]).encode()
        self.target = md5

    def validate(self):
        if len(self.file_contents) != 72:
            raise InvalidFileException(
                "Gesture pattern file needs to be exactly 72 bytes"
            )

    def generate_hashparameters(self, possible_pin: int) -> HashParameter:
        return HashParameter(
            salt=self.salt,
            target=self.target,
            possible=str(possible_pin).zfill(self.length).encode(),
        )


class NewPINCracker(AbstractPINCracker):
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

    def generate_hashparameters(self, possible_pin: int) -> HashParameter:
        return HashParameter(
            salt=self.salt,
            target=self.signature,
            possible=str(possible_pin).zfill(self.length).encode(),
            kwargs={"meta": self.meta},
        )
