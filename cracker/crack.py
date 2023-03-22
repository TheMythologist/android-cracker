from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional
import multiprocessing


@dataclass
class Parameter:
    target: bytes
    possible: bytes
    salt: Optional[bytes] = None
    kwargs: Optional[dict[str, Any]] = None


def crack(func: Callable[[Parameter], Any], params: Iterable[Parameter]) -> Any:
    ncores = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(ncores)
    result = pool.map(func, params)
    pool.close()
    pool.join()
    return next((r for r in result if r is not None), None)
