import multiprocessing
from io import BufferedReader, BytesIO
from typing import Iterable

from cracker.AbstractCracker import AbstractCracker
from cracker.CrackManager import CrackManager, run_crack


class AbstractPasswordCracker(AbstractCracker):
    def __init__(
        self,
        file: BufferedReader,
        wordlist_file: BufferedReader,
        cracker: type[CrackManager],
    ):
        super().__init__(file, cracker)
        self.wordlist_file = wordlist_file

    def run(self):
        queue = multiprocessing.Queue()
        found = multiprocessing.Event()
        result = multiprocessing.Queue()
        crackers = run_crack(self.cracker, queue, found, result)

        for word in self.parse_wordlist(self.wordlist_file):
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
