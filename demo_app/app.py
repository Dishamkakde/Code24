"""Deliberately vulnerable Flask + SQLite notes app for DAMage CTRL testing.
Planted test cases:
  a. SQL injection in /login (f-string query with username/password)
  b. Broken access control (IDOR) in GET /notes/<note_id> (no ownership check)
  c. Path traversal in GET /download/<filename> (os.path.join with user filename)
  d. Hardcoded secret_key and debug=True
  e. One FALSE POSITIVE: a query using an f-string where the only inserted value is wrapped in int(...)
"""
import os
import sqlite3
import secrets
from flask import Flask, request, jsonify, session, send_file, abort

app = Flask(__name__)

# Planted: Hardcoded secret_key
app.secret_key = "damage_ctrl_demo_insecure_secret_key_12345"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "notes.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        content TEXT
    )
    """)
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM notes")
    cursor.execute("INSERT INTO users (id, username, password) VALUES (1, 'alice', 'password123')")
    cursor.execute("INSERT INTO users (id, username, password) VALUES (2, 'bob', 'password456')")
    cursor.execute("INSERT INTO notes (id, user_id, title, content) VALUES (1, 1, 'Alice Secret Note', 'Confidential note for Alice only.')")
    cursor.execute("INSERT INTO notes (id, user_id, title, content) VALUES (2, 2, 'Bob Secret Note', 'Confidential note for Bob only.')")
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize SQLite tables on module import
init_db()

# Create sample upload file
sample_file = os.path.join(UPLOAD_FOLDER, "sample.txt")
with open(sample_file, "w", encoding="utf-8") as f:
    f.write("Sample document content inside uploads directory.")

secret_file = os.path.join(BASE_DIR, "server_secret.txt")
with open(secret_file, "w", encoding="utf-8") as f:
    f.write("FLAG_DAMage_CTRL_CONFIDENTIAL_SECRET")


@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "online", "service": "DAMage CTRL Demo Notes App"}), 200


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    conn = get_db()
    cursor = conn.cursor()
    # Planted SQL Injection: f-string query with username/password
    cursor.execute(f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'")
    user = cursor.fetchone()
    conn.close()
    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return jsonify({"status": "success", "user_id": user["id"], "username": user["username"]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/notes/<int:note_id>", methods=["GET"])
def get_note(note_id):
    conn = get_db()
    cursor = conn.cursor()
    # Planted IDOR: Broken access control on notes retrieval (no user_id check)
    cursor.execute("SELECT id, title, content FROM notes WHERE id = ?", (note_id,))
    note = cursor.fetchone()
    conn.close()
    if note:
        return jsonify({"id": note["id"], "title": note["title"], "content": note["content"]})
    return jsonify({"error": "Note not found"}), 404


@app.route("/download/<path:filename>", methods=["GET"])
def download(filename):
    # Planted Path Traversal: os.path.join with user supplied filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return jsonify({"error": "File not found"}), 404


@app.route("/user-notes-count", methods=["GET"])
def user_notes_count():
    user_id = request.args.get("user_id", "1")
    conn = get_db()
    cursor = conn.cursor()
    # Planted False Positive: f-string query where only inserted value is wrapped in int(...)
    cursor.execute(f"SELECT COUNT(*) FROM notes WHERE user_id = {int(user_id)}")
    count = cursor.fetchone()[0]
    conn.close()
    return jsonify({"user_id": int(user_id), "count": count})


if __name__ == "__main__":
    # Planted: debug=True
    app.run(host="0.0.0.0", port=5000, debug=True)
