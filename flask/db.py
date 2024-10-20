import sqlite3
from werkzeug.security import generate_password_hash

# 데이터베이스 파일 경로
USER_DB = 'users.db'
SUGGESTION_DB = 'suggestions.db'

def initialize_user_db():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()

    # users 테이블 생성
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')

    # admins 테이블 생성
    c.execute('''CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')

    conn.commit()
    conn.close()

def initialize_suggestion_db():
    conn = sqlite3.connect(SUGGESTION_DB)
    c = conn.cursor()

    # suggestions 테이블 생성
    c.execute('''CREATE TABLE IF NOT EXISTS suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    suggestion TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')

    conn.commit()
    conn.close()

def create_admin_user():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()

    username = 'hwabong'  # 관리자 사용자 이름
    password_hash = generate_password_hash('hwabong1234')  # 관리자 비밀번호 해시

    # 관리자 계정이 존재하지 않는 경우에만 생성
    c.execute("SELECT * FROM admins WHERE username = ?", (username,))
    if not c.fetchone():
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, password_hash))
        conn.commit()

    conn.close()

# 실행 시 데이터베이스 초기화 및 관리자 계정 생성
if __name__ == "__main__":
    initialize_user_db()
    initialize_suggestion_db()
    create_admin_user()
    print("Database initialized and admin user created.")
