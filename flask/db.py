import mysql.connector
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

load_dotenv()

# MySQL 연결 정보
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        if conn.is_connected():
            return conn
    except mysql.connector.Error as e:
        print(f"Error: {e}")
        return None

def initialize_user_db():
    conn = get_db_connection()
    if conn:
        c = conn.cursor()

        # users 테이블 생성
        c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        ''')

        # admins 테이블 생성
        c.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        ''')

        conn.commit()
        conn.close()

def initialize_suggestion_db():
    conn = get_db_connection()
    if conn:
        c = conn.cursor()

        # suggestions 테이블 생성
        c.execute('''
        CREATE TABLE IF NOT EXISTS suggestions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            suggestion TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        conn.commit()
        conn.close()

def create_admin_user():
    conn = get_db_connection()
    if conn:
        c = conn.cursor()

        username = '사용자'  # 관리자 사용자 이름
        password_hash = generate_password_hash('비밀번호')  # 관리자 비밀번호 해시

        # 관리자 계정이 존재하지 않는 경우에만 생성
        c.execute("SELECT * FROM admins WHERE username = %s", (username,))
        if not c.fetchone():
            c.execute("INSERT INTO admins (username, password) VALUES (%s, %s)", (username, password_hash))
            conn.commit()

        conn.close()

# 실행 시 데이터베이스 초기화 및 관리자 계정 생성
if __name__ == "__main__":
    initialize_user_db()
    initialize_suggestion_db()
    create_admin_user()
    print("Database initialized and admin user created.")
