from flask import Flask, render_template, request, redirect, url_for, session, flash
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pytz

from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error

load_dotenv()

# AWS RDS MySQL 연결 정보
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

app = Flask(__name__)
app.secret_key = 'yoursecretkey'

# 금칙어 목록
BAD_WORDS = []

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
    except Error as e:
        print(f"Error: {e}")
        return None

def is_valid_student_id(student_id):
    return re.match(r'^\d{4}$', student_id)

def contains_bad_words(text):
    return any(word in text for word in BAD_WORDS)

def can_submit(user_id):
    conn = get_db_connection()
    if conn:
        c = conn.cursor()
        c.execute("SELECT timestamp FROM suggestions WHERE user_id = %s ORDER BY timestamp DESC LIMIT 1", (user_id,))
        last_submission = c.fetchone()
        conn.close()

        if last_submission:
            last_submission_time = datetime.strptime(last_submission[0], '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.UTC) 
            if datetime.utcnow().replace(tzinfo=pytz.UTC)  - last_submission_time < timedelta(hours=1):
                return False
        return True
    return False

def get_admin_credentials():
    conn = get_db_connection()
    if conn:
        c = conn.cursor()
        c.execute("SELECT username, password FROM admins WHERE id = 1")
        admin = c.fetchone()
        conn.close()
        return admin
    return None

def get_user_id(username):
    conn = get_db_connection()
    if conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = %s", (username,))
        user_id = c.fetchone()
        conn.close()
        return user_id[0] if user_id else None
    return None

# 메인화면
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'logged_in' not in session:
            flash('로그인 후에 건의를 제출할 수 있습니다.', 'error')
            return redirect(url_for('login'))
        
        username = session.get('username')
        if not username:
            flash('사용자 이름을 찾을 수 없습니다.', 'error')
            return redirect(url_for('login'))

        user_id = get_user_id(username)
        if not user_id:
            flash('사용자 ID를 찾을 수 없습니다.', 'error')
            return redirect(url_for('index'))

        suggestion = request.form.get('suggestion')

        if not can_submit(user_id):
            flash('제출 빈도를 초과했습니다. 나중에 다시 시도해 주세요.', 'error')
        elif contains_bad_words(suggestion):
            flash('건의 내용에 금칙어가 포함되어 있습니다.', 'error')
        else:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO suggestions (user_id, suggestion, timestamp) VALUES (%s, %s, %s)", 
                      (user_id, suggestion, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            conn.close()
            flash('제출 완료되었습니다!', 'success')
            return redirect(url_for('index'))

    user_logged_in = 'logged_in' in session
    username = session.get('username', '')  # 사용자 이름 가져오기

    return render_template('index.html', user_logged_in=user_logged_in, username=username)

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']

        # 학번 유효성 검사 추가
        if not is_valid_student_id(username):
            flash('학번은 4자리 숫자여야 합니다.', 'error')
            return render_template('register.html')

        password = request.form['password']
        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password_hash))
            conn.commit()
        except mysql.connector.IntegrityError:
            flash('이미 등록된 학번입니다.', 'error')
            conn.close()
            return render_template('register.html')
        conn.close()
        flash('회원가입 완료. 로그인 해주세요.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# 로그인 창
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username = %s", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['logged_in'] = True
            session['user_id'] = user[0]
            session['username'] = username  # 학번 세션 추가
            return redirect(url_for('index'))
        else:
            flash('로그인 실패: 올바르지 않은 학번 또는 비밀번호입니다.', 'error')

    return render_template('login.html')

# 관리자 로그인
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = get_admin_credentials()
        if admin and admin[0] == username and check_password_hash(admin[1], password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin'))
        else:
            flash('로그인 실패: 올바르지 않은 관리자 학번 또는 비밀번호입니다.', 'error')

    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('관리자 로그아웃되었습니다.', 'success')
    return redirect(url_for('index'))

# 관리자 창
@app.route('/admin')
def admin():
    if 'admin_logged_in' not in session:
        flash('관리자 로그인 후에 접근할 수 있습니다.', 'error')
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM suggestions ORDER BY timestamp DESC')
    suggestions = c.fetchall()
    conn.close()

    # 사용자 이름을 가져오기 위한 추가 쿼리
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT id, username FROM users')
    user_names = dict(c.fetchall())  # 모든 사용자 ID와 이름을 미리 가져옴
    conn.close()

    return render_template('admin.html', suggestions=suggestions, user_names=user_names)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('username', None)
    flash('로그아웃되었습니다.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
