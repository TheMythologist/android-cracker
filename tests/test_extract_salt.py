from pathlib import Path
from cracker.parsers.salt import new_extract_info, old_extract_salt


def test_old_extract_salt():
    assert old_extract_salt(1059186646558953472) == b"eb2fca4aafbd000"


def test_new_extract_salt():
    assert new_extract_info(Path("sample/keys/new_pin_2345.key").read_bytes()) == (
        b"\x02\x99\xbe2ze\x9dmF\x01\x00\x00\x00\x00\x00\x00\x00",
        b"a*<\xf0$\xad\xcc\xe8",
        b'\xd3;L\xe2{(\xeb@\x8c\xddF\xacU\x19y9\xbb9"\xd0\xf5\x97\xa0\x01L\t\xfd\xe7\xb99\x06\x12',
    )
