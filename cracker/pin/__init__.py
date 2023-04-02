import multiprocessing
from io import BufferedReader

from cracker.AbstractCracker import AbstractCracker
from cracker.CrackManager import CrackManager, run_crack
from cracker.policy import DevicePolicy


class AbstractPINCracker(AbstractCracker):
    def __init__(
        self,
        file: BufferedReader,
        device_policy: DevicePolicy,
        cracker: type[CrackManager],
    ):
        super().__init__(file, cracker)
        self.device_policy = device_policy

    def run(self):
        queue = multiprocessing.Queue()
        found = multiprocessing.Event()
        result = multiprocessing.Queue()
        crackers = run_crack(self.cracker, queue, found, result)

        for possible_pin in range(10**self.device_policy.length):
            if found.is_set():
                for cracker in crackers:
                    cracker.stop()
                break
            queue.put(self.generate_hashparameters(possible_pin))

        for cracker in crackers:
            cracker.join()
        queue.cancel_join_thread()
        print(f"Found key: {result.get()}")
