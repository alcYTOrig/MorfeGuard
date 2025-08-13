import bcrypt
import sqlite3  # Пример с SQLite, можно использовать любую БД


def register_user(username: str, password: str):
    # Хеширование пароля с автоматической генерацией соли
    password_bytes = password.encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    # Сохранение в базу данных
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Создание таблицы (если не существует)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
    ''')

    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        ''', (username, hashed_password))
        conn.commit()
        print(f"Пользователь {username} успешно зарегистрирован!")
    except sqlite3.IntegrityError:
        print(f"Ошибка: Пользователь {username} уже существует")
    finally:
        conn.close()


def verify_user(username: str, password: str) -> bool:
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT password_hash FROM users WHERE username = ?
    ''', (username,))

    if row := cursor.fetchone():
        stored_hash = row[0]
        password_bytes = password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, stored_hash)

    return False  # Пользователь не найден


# Пример использования
if __name__ == "__main__":
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")

    register_user(username, password)
    print(verify_user(username, password))