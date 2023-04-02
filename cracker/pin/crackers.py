import struct
from io import BufferedReader

from cracker.CrackManager import HashParameter
from cracker.exception import InvalidFileException, MissingArgumentException
from cracker.hashcrack import MD5Crack, ScryptCrack
from cracker.pin import AbstractPINCracker
from cracker.policy import DevicePolicy


class OldPINCracker(AbstractPINCracker):
    # Android versions <= 5.1

    def __init__(
        self,
        file: BufferedReader,
        device_policy: DevicePolicy | None,
        salt: int | None,
        **kwargs
    ):
        if salt is None:
            raise MissingArgumentException("Salt or database argument is required")
        super().__init__(file, device_policy, MD5Crack)
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
            possible=str(possible_pin).zfill(self.device_policy.length).encode(),
        )


class NewPINCracker(AbstractPINCracker):
    # Android versions <= 8.0, >= 6.0

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

    def generate_hashparameters(self, possible_pin: int) -> HashParameter:
        return HashParameter(
            salt=self.salt,
            target=self.signature,
            possible=str(possible_pin).zfill(self.device_policy.length).encode(),
            kwargs={"meta": self.meta},
        )
