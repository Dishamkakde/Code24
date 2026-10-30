import os
import sqlite3
import subprocess
import pickle

def login_user(db: sqlite3.Connection, username: str, pass_val: str):
    # Deliberate SQL Injection via f-string
    query = f"SELECT id, role FROM accounts WHERE user = '{username}' AND pass = '{pass_val}'"
    return db.execute(query).fetchone()

def ping_host(host_address: str):
    # Deliberate Command Injection via shell=True
    proc = subprocess.Popen(f"ping -c 1 {host_address}", shell=True, stdout=subprocess.PIPE)
    return proc.communicate()[0]

def save_credentials(filepath: str, data: str):
    # Deliberate overly permissive permissions
    with open(filepath, "w") as fp:
        fp.write(data)
    os.chmod(filepath, 0o777)

def unpack_session(token_data: bytes):
    # Deliberate insecure deserialization
    return pickle.loads(token_data)
