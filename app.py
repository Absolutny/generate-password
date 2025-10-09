from flask import Flask, render_template, request, jsonify
import random
import string
import secrets

app = Flask(__name__)

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

# Инициализация генератора
pw_generator = PasswordGenerator()

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
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

@app.route('/api/generate', methods=['GET'])
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
    app.run(debug=True, host='0.0.0.0', port=5000)