from cracker.locksettings import retrieve_salt


def test_locksettings():
    assert retrieve_salt("sample/locksettings.db") == 1059186646558953472
