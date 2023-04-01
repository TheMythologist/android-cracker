import multiprocessing
from io import BufferedReader

from cracker.AbstractCracker import AbstractCracker
from cracker.CrackManager import CrackManager, run_crack


class AbstractPINCracker(AbstractCracker):
    def __init__(self, file: BufferedReader, length: int, cracker: type[CrackManager]):
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
