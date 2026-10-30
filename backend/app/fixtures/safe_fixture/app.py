import os
import sqlite3
import subprocess
import json

def login_user(db: sqlite3.Connection, username: str, pass_val: str):
    # Safe parameterized query
    query = "SELECT id, role FROM accounts WHERE user = ? AND pass = ?"
    return db.execute(query, (username, pass_val)).fetchone()

def ping_host(host_address: str):
    # Safe subprocess execution without shell
    proc = subprocess.run(["ping", "-c", "1", host_address], shell=False, capture_output=True, text=True)
    return proc.stdout

def save_credentials(filepath: str, data: str):
    # Restrictive secure file permissions
    with open(filepath, "w") as fp:
        fp.write(data)
    os.chmod(filepath, 0o600)

def unpack_session(token_data: str):
    # Safe JSON deserialization
    return json.loads(token_data)
