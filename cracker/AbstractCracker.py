from abc import ABC, abstractmethod
from io import BufferedReader

from CrackManager import CrackManager, HashParameter


class AbstractCracker(ABC):
    def __init__(self, gesture_file: BufferedReader, cracker: CrackManager):
        self.gesture_file_contents = gesture_file.read()
        self.validate()
        self.cracker = cracker

    @abstractmethod
    def generate_hashparameters(self, word: bytes) -> HashParameter:
        ...

    @abstractmethod
    def validate(self) -> None:
        ...

    @abstractmethod
    def run(self):
        ...
