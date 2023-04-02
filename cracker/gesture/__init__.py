import multiprocessing
from io import BufferedReader
from itertools import permutations
from string import digits

from cracker.AbstractCracker import AbstractCracker
from cracker.CrackManager import CrackManager, run_crack
from cracker.gesture.printer import print_graphical_gesture
from cracker.policy import DevicePolicy


class AbstractGestureCracker(AbstractCracker):
    def __init__(
        self,
        file: BufferedReader,
        device_policy: DevicePolicy,
        cracker: type[CrackManager],
        **kwargs,
    ):
        super().__init__(file, cracker)
        self.device_policy = device_policy

    def run(self):
        queue = multiprocessing.Queue()
        found = multiprocessing.Event()
        result = multiprocessing.Queue()
        crackers = run_crack(self.cracker, queue, found, result)

        for possible_num in permutations(digits, self.device_policy.length):
            if found.is_set():
                for cracker in crackers:
                    cracker.stop()
                break
            queue.put(self.generate_hashparameters("".join(possible_num)))

        for cracker in crackers:
            cracker.join()
        queue.cancel_join_thread()
        ans = result.get()
        print(f"Found key: {ans}")
        print_graphical_gesture(ans, self.first_num)
