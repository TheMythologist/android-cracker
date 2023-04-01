import multiprocessing
from io import BufferedReader
from itertools import permutations
from string import digits

from cracker.AbstractCracker import AbstractCracker
from cracker.CrackManager import CrackManager, run_crack


class AbstractGestureCracker(AbstractCracker):
    def __init__(
        self, file: BufferedReader, length: int, cracker: type[CrackManager], **kwargs
    ):
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
