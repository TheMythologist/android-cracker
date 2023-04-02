import binascii
import hashlib
import struct
from io import BufferedReader

from cracker.CrackManager import HashParameter
from cracker.exception import InvalidFileException
from cracker.gesture import AbstractGestureCracker
from cracker.hashcrack import ScryptCrack, SHA1Crack
from cracker.policy import DevicePolicy


class OldGestureCracker(AbstractGestureCracker):
    # Android versions <= 5.1
    first_num = 0

    def __init__(
        self, file: BufferedReader, device_policy: DevicePolicy | None, **kwargs
    ):
        super().__init__(file, device_policy, SHA1Crack)
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
    # Android versions <= 8.0, >= 6.0
    first_num = 1

    def __init__(
        self, file: BufferedReader, device_policy: DevicePolicy | None, **kwargs
    ):
        super().__init__(file, device_policy, ScryptCrack)
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
