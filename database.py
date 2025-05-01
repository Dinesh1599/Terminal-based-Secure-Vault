import sqlite3
import os

DB_FILE = 'vault.db'

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():  #Database initialization
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            salt BLOB NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            encrypted_data TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

def create_user(uname, pwd_hash):
    conn = get_db()
    c = conn.cursor()
    salt = os.urandom(16)
    c.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', (uname, pwd_hash, salt))
    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    return dict(row) if row else None

def add_vault_entry(user_id, title, encrypted_data):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO vault (user_id, title, encrypted_data) VALUES (?, ?, ?)', (user_id, title, encrypted_data))
    conn.commit()
    conn.close()

def get_vault_entries(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM vault WHERE user_id = ?', (user_id,))
    rows = c.fetchall()
    return [dict(row) for row in rows]    



