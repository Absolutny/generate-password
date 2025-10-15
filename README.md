# 🔐 SecurePass Generator

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)
![SQLite](https://img.shields.io/badge/Database-SQLite3-lightgrey.svg)
![Security](https://img.shields.io/badge/Security-SHA256--Hashing-orange.svg)
![Theme](https://img.shields.io/badge/Theme-Dark--Mode-black.svg)

**Современный генератор паролей с системой аутентификации и темным интерфейсом**

[Особенности](#-особенности) • [Быстрый старт](#-быстрый-старт) • [Демо](#-демо) • [Документация](#-документация)

</div>

## 🚀 О проекте

SecurePass Generator - это полнофункциональное веб-приложение для создания криптографически безопасных паролей. Приложение сочетает в себе современный темный дизайн с надежной системой аутентификации, обеспечивая максимальную безопасность и удобство использования.

### 🎯 Ключевые преимущества

- ✅ **Обязательная авторизация** - доступ только для зарегистрированных пользователей
- ✅ **4 уровня сложности** - от простых до максимально защищенных паролей
- ✅ **Темная тема** - современный дизайн с заботой о ваших глазах
- ✅ **Полная анонимность** - мы не храним сгенерированные пароли
- ✅ **Адаптивный интерфейс** - работает на любых устройствах

## 🛠 Технологический стек

| Компонент | Технология |
|-----------|------------|
| **Backend** | Flask, Python 3.8+ |
| **Database** | SQLite3 с параметризованными запросами |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Security** | SHA-256 хеширование, сессии Flask |
| **Styling** | CSS Grid, Flexbox, CSS Variables |
| **Icons** | Emoji для лучшей визуализации |

## 📦 Быстрый старт

### Предварительные требования

- Python 3.8 или новее
- pip (пакетный менеджер Python)
- Доступ в интернет (для загрузки зависимостей)

### Установка за 3 шага

```bash
# 1. Клонирование репозитория
git clone https://github.com/Absolutny/generate-password.git
cd generate-password

# 2. Установка зависимостей
pip install -r requirements.txt

# 3. Запуск приложения
python app.py
