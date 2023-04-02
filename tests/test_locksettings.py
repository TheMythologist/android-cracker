import re

import pytest

from cracker.exception import InvalidFileException
from cracker.locksettings import retrieve_salt


def test_locksetting():
    assert retrieve_salt("sample/locksettings.db") == 1059186646558953472


def test_bad_locksettings():
    with pytest.raises(
        InvalidFileException,
        match=re.escape('Invalid salt value in database (found "asdf")'),
    ):
        retrieve_salt("sample/invalidlocksettings.db")
    with pytest.raises(
        InvalidFileException,
        match=re.escape("No salt value in database"),
    ):
        retrieve_salt("sample/badlocksettings.db")
