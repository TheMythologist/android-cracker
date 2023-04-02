import multiprocessing
from abc import ABC, abstractmethod
from dataclasses import dataclass
from multiprocessing.synchronize import Event
from queue import Empty
from typing import Any, Optional

from typing_extensions import Self


@dataclass
class HashParameter:
    target: Any
    possible: bytes
    salt: Optional[bytes] = None
    kwargs: Optional[dict[str, Any]] = None


class CrackManager(ABC):
    def __init__(
        self,
        queue: multiprocessing.Queue,
        found: Event,
        output_queue: multiprocessing.Queue,
    ):
        self.queue = queue
        self.found = found
        self.result = output_queue
        self.process = multiprocessing.Process(target=self.run, daemon=True)

    def start(self) -> Self:
        self.process.start()
        return self

    def stop(self) -> None:
        self.process.terminate()

    def join(self) -> None:
        self.process.join()

    def run(self) -> None:
        try:
            while not self.found.is_set():
                params = self.queue.get(timeout=10)
                if ans := self.crack(params):
                    self.result.put(ans)
                    self.found.set()
                    return
        except Empty:
            return

    @staticmethod
    @abstractmethod
    def crack(params: HashParameter):
        ...


def run_crack(
    cracker: type[CrackManager],
    queue: multiprocessing.Queue,
    found: Event,
    result: multiprocessing.Queue,
) -> list[CrackManager]:
    return [
        cracker(queue, found, result).start()
        for _ in range(multiprocessing.cpu_count())
    ]
