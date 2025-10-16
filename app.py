from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import random
import string
import secrets
import sqlite3
from datetime import datetime
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

class Database:
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        """Инициализация базы данных"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Создаем пользователя admin если его нет
        admin_hash = hashlib.sha256('1234'.encode()).hexdigest()
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password_hash, created_at)
            VALUES (?, ?, ?)
        ''', ('admin', admin_hash, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def add_user(self, username, password):
        """Добавление нового пользователя"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
            ''', (username, password_hash, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def get_user(self, username):
        """Получение пользователя по имени"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'password_hash': user[2],
                'created_at': user[3]
            }
        return None
    
    def verify_password(self, username, password):
        """Проверка пароля"""
        user = self.get_user(username)
        if user:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return password_hash == user['password_hash']
        return False
    
    def change_password(self, username, new_password):
        """Смена пароля"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        new_password_hash = hashlib.sha256(new_password.encode()).hexdigest()
        
        cursor.execute('''
            UPDATE users SET password_hash = ? WHERE username = ?
        ''', (new_password_hash, username))
        
        conn.commit()
        conn.close()
    
    def delete_user(self, username):
        """Удаление пользователя"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        
        conn.commit()
        conn.close()

class PasswordGenerator:
    def __init__(self):
        self.levels = {
            'easy': {
                'length': 8,
                'use_lowercase': True,
                'use_uppercase': False,
                'use_numbers': False,
                'use_special': False
            },
            'normal': {
                'length': 12,
                'use_lowercase': True,
                'use_uppercase': True,
                'use_numbers': True,
                'use_special': False
            },
            'hard': {
                'length': 16,
                'use_lowercase': True,
                'use_uppercase': True,
                'use_numbers': True,
                'use_special': True
            },
            'impossible': {
                'length': 20,
                'use_lowercase': True,
                'use_uppercase': True,
                'use_numbers': True,
                'use_special': True
            }
        }
    
    def generate_password(self, level, custom_length=None):
        """Генерация пароля по уровню сложности"""
        if level not in self.levels:
            level = 'normal'
        
        config = self.levels[level].copy()
        
        # Если указана кастомная длина, используем её
        if custom_length and custom_length > 0:
            config['length'] = custom_length
        
        characters = ""
        
        # Формируем набор символов в зависимости от настроек
        if config['use_lowercase']:
            characters += string.ascii_lowercase
        if config['use_uppercase']:
            characters += string.ascii_uppercase
        if config['use_numbers']:
            characters += string.digits
        if config['use_special']:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Если не выбран ни один тип символов, используем буквы нижнего регистра
        if not characters:
            characters = string.ascii_lowercase
        
        # Генерируем безопасный пароль
        password = ''.join(secrets.choice(characters) for _ in range(config['length']))
        
        return password
    
    def check_password_strength(self, password):
        """Проверка сложности пароля"""
        score = 0
        if len(password) >= 8:
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        if score <= 2:
            return "Слабый"
        elif score <= 4:
            return "Средний"
        else:
            return "Сильный"

# Инициализация
db = Database()
pw_generator = PasswordGenerator()

def login_required(f):
    """Декоратор для проверки авторизации"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Пожалуйста, войдите в систему для доступа к этой странице.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Главная страница - перенаправление на логин"""
    if 'username' in session:
        return redirect(url_for('generator'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Авторизация пользователя"""
    if 'username' in session:
        return redirect(url_for('generator'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if db.verify_password(username, password):
            session['username'] = username
            flash(f'Добро пожаловать, {username}!')
            return redirect(url_for('generator'))
        else:
            flash('Неверное имя пользователя или пароль!')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация пользователя"""
    if 'username' in session:
        return redirect(url_for('generator'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Пароли не совпадают!')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Имя пользователя должно содержать минимум 3 символа!')
            return render_template('register.html')
        
        if len(password) < 4:
            flash('Пароль должен содержать минимум 4 символа!')
            return render_template('register.html')
        
        if db.add_user(username, password):
            flash('Регистрация успешна! Теперь вы можете войти.')
            return redirect(url_for('login'))
        else:
            flash('Пользователь с таким именем уже существует!')
    
    return render_template('register.html')

@app.route('/generator')
@login_required
def generator():
    """Страница генератора паролей"""
    return render_template('generator.html')

@app.route('/generate', methods=['POST'])
@login_required
def generate_password():
    """Генерация пароля"""
    try:
        level = request.form.get('level', 'normal')
        custom_length = request.form.get('custom_length', type=int)
        
        # Генерируем пароль
        password = pw_generator.generate_password(level, custom_length)
        
        # Проверяем сложность
        strength = pw_generator.check_password_strength(password)
        
        return render_template('result.html', 
                             password=password, 
                             level=level.capitalize(),
                             strength=strength,
                             length=len(password))
    
    except Exception as e:
        return render_template('result.html', 
                             error=f"Ошибка генерации: {str(e)}")

@app.route('/profile')
@login_required
def profile():
    """Страница профиля"""
    user = db.get_user(session['username'])
    return render_template('profile.html', user=user)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """Смена пароля"""
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    username = session['username']
    
    if not db.verify_password(username, current_password):
        flash('Текущий пароль неверен!')
        return redirect(url_for('profile'))
    
    if len(new_password) < 4:
        flash('Новый пароль должен содержать минимум 4 символа!')
        return redirect(url_for('profile'))
    
    db.change_password(username, new_password)
    flash('Пароль успешно изменен!')
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    """Удаление аккаунта"""
    password = request.form['confirm_password']
    username = session['username']
    
    if not db.verify_password(username, password):
        flash('Неверный пароль!')
        return redirect(url_for('profile'))
    
    db.delete_user(username)
    session.pop('username', None)
    flash('Ваш аккаунт был удален.')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Выход из системы"""
    session.pop('username', None)
    flash('Вы вышли из системы.')
    return redirect(url_for('login'))

@app.route('/api/generate', methods=['GET'])
@login_required
def api_generate():
    """API для генерации пароля"""
    try:
        level = request.args.get('level', 'normal')
        length = request.args.get('length', type=int)
        
        password = pw_generator.generate_password(level, length)
        strength = pw_generator.check_password_strength(password)
        
        return jsonify({
            'password': password,
            'level': level,
            'strength': strength,
            'length': len(password)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=1839)

