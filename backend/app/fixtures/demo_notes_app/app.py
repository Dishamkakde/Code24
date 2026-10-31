"""Deliberately vulnerable notes app (local fixture). DO NOT use in production."""
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(BASE_DIR, "uploads")


def init_db():
    db = sqlite3.connect(":memory:")
    db.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT);
    CREATE TABLE notes(id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT);
    INSERT INTO users VALUES (1,'alice','alicepw'),(2,'bob','bobpw');
    INSERT INTO notes VALUES (1,1,'alice private note'),(2,2,'bob private note');
    """)
    return db


def login(db, username, password):
    row = db.execute(f"SELECT id FROM users WHERE username='{username}' AND password='{password}'").fetchone()
    return row[0] if row else None


def get_note(db, user_id, note_id):
    row = db.execute("SELECT body FROM notes WHERE id = ?", (note_id,)).fetchone()
    return row[0] if row else None


def list_notes(db, user_id):
    uid = int(user_id)
    rows = db.execute(f"SELECT body FROM notes WHERE owner_id = {uid}").fetchall()
    return [r[0] for r in rows]


def read_attachment(name):
    with open(os.path.join(UPLOADS, name), "r") as f:
        return f.read()


def upload_attachment(name, content):
    path = os.path.realpath(os.path.join(UPLOADS, os.path.basename(name)))
    root = os.path.realpath(UPLOADS)
    if os.path.commonpath([path, root]) != root:
        raise PermissionError("path escapes uploads directory")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return True

