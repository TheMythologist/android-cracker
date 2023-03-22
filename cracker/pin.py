from abc import ABC, abstractmethod
import multiprocessing
import struct
from io import BufferedReader

from cracking import CrackManager, HashParameter, run_crack
from exception import InvalidFileException
from hashcrack import MD5Crack, ScryptCrack


class PINCrack(ABC):
    def __init__(self, gesture_file: BufferedReader, length: int, cracker: CrackManager):
        self.gesture_file = gesture_file
        self.length = length
        self.cracker = cracker

    @abstractmethod
    def generate_hashparameters(self, possible_pin: int) -> HashParameter:
        ...

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
        queue.cancel_join_thread()
        for cracker in crackers:
            cracker.join()


class OldPINCrack(PINCrack):
    def __init__(self, gesture_file: BufferedReader, length: int, salt: int):
        super().__init__(gesture_file, length, MD5Crack)
        # Android versions <= 5.1
        gesture_file_contents = gesture_file.read()
        if len(gesture_file_contents) != 72:
            raise InvalidFileException("Gesture pattern file needs to be exactly 72 bytes")
        combined_hash = gesture_file_contents.decode().casefold().encode()
        sha1, md5 = combined_hash[:40], combined_hash[40:]
        # Get salt
        salt1 = hex(salt & 0xFFFFFFFF)
        salt2 = hex(salt >> 32 & 0xFFFFFFFF)
        self.salt = (salt2[2:] + salt1[2:]).encode()
        self.target = md5

    def generate_hashparameters(self, possible_pin: int) -> HashParameter:
        return HashParameter(
            salt=self.salt,
            target=self.target,
            possible=str(possible_pin).zfill(self.length).encode(),
        )


class NewPINCrack(PINCrack):
    def __init__(self, gesture_file: BufferedReader, length: int):
        super().__init__(gesture_file, length, ScryptCrack)
        # Android versions < 8.0, >= 6.0
        gesture_file_contents = gesture_file.read()
        if len(gesture_file_contents) != 58:
            raise InvalidFileException("Gesture pattern file needs to be exactly 58 bytes")
        s = struct.Struct("<17s 8s 32s")
        self.meta, self.salt, self.signature = s.unpack_from(gesture_file_contents)

    def generate_hashparameters(self, possible_pin: int) -> HashParameter:
        return HashParameter(
            salt=self.salt,
            target=self.signature,
            possible=str(possible_pin).zfill(self.length).encode(),
            kwargs={"meta": self.meta},
        )
