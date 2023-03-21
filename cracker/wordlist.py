from io import TextIOWrapper
from typing import Iterable


def parse_wordlist(wordlist: TextIOWrapper) -> Iterable[bytes]:
    for word in wordlist:
        yield word.strip()
