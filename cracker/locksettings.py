import sqlite3
from contextlib import closing


def retrieve_salt(locksettingdb_path: str) -> int:
    with closing(sqlite3.connect(locksettingdb_path)) as con:
        with closing(con.cursor()) as cur:
            cur.execute(
                "SELECT value FROM locksettings WHERE name='lockscreen.password_salt'"
            )
            return int(cur.fetchone()[0])
