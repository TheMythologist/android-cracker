import multiprocessing
from abc import abstractmethod
from io import BufferedReader
from itertools import permutations
from multiprocessing.queues import Queue
from queue import Empty
from string import digits
from typing import Any

from cracker.AbstractCracker import AbstractCracker
from cracker.CrackManager import CrackManager, HashParameter, run_crack
from cracker.exception import MissingArgumentException
from cracker.gesture.printer import print_graphical_gesture
from cracker.policy import DevicePolicy


class AbstractGestureCracker(AbstractCracker):
    def __init__(
        self,
        file: BufferedReader,
        device_policy: DevicePolicy | None,
        cracker: type[CrackManager],
        **kwargs: Any,
    ) -> None:
        if device_policy is None:
            raise MissingArgumentException("Length or policy argument is required")
        super().__init__(file, cracker)
        self.device_policy = device_policy

    @property
    @abstractmethod
    def first_num(self) -> int: ...

    def run(self) -> None:
        queue: Queue[HashParameter] = multiprocessing.Queue()
        result: Queue[str] = multiprocessing.Queue()
        crackers = run_crack(self.cracker, queue, result)

        for possible_num in permutations(digits, self.device_policy.length):
            if not result.empty():
                for cracker in crackers:
                    cracker.stop()
                break
            queue.put(self.generate_hashparameters("".join(possible_num)))

        for cracker in crackers:
            cracker.join()
        queue.cancel_join_thread()
        try:
            ans = result.get(block=False)
            print(f"Found key: {ans}")
            print_graphical_gesture(ans, self.first_num)
        except Empty:
            print("No key found")
