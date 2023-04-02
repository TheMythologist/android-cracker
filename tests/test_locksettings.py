import re

import pytest

from cracker.exception import InvalidFileException
from cracker.locksettings import retrieve_salt


def test_locksetting():
    assert retrieve_salt("sample/locksettings/unsigned_locksettings.db") == 1059186646558953472
    assert retrieve_salt("sample/locksettings/signed_locksettings.db") == 17387557427150598144


def test_bad_locksettings():
    with pytest.raises(
        InvalidFileException,
        match=re.escape("No salt value in database"),
    ):
        retrieve_salt("sample/locksettings/bad_locksettings.db")
