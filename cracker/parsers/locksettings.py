import sqlite3
from contextlib import closing

from cracker.exception import InvalidFileException


def retrieve_salt(locksettingdb_path: str) -> int:
    with closing(sqlite3.connect(locksettingdb_path)) as con:
        with closing(con.cursor()) as cur:
            cur.execute(
                "SELECT value FROM locksettings WHERE name='lockscreen.password_salt'"
            )
            if (result := cur.fetchone()) is None:
                raise InvalidFileException("No salt value in database")
    return int(result[0]) & 0xFFFFFFFFFFFFFFFF
