import psycopg2
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

@dataclass
class User:
    user_id: Optional[int]
    username: str
    email: str
    password_hash: str
    full_name: str
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

class UserManager:
    def __init__(self, db_connection):
        self.conn = db_connection

    def save_user(self, user: User):
        """Создает нового пользователя или обновляет существующего."""
        with self.conn.cursor() as cursor:
            if user.user_id:
                cursor.execute("""
                    SELECT 1 FROM asgu.users WHERE user_id = %s;
                """, (user.user_id,))
                if cursor.fetchone():
                    cursor.execute("""
                        UPDATE asgu.users 
                        SET username = %s, email = %s, password_hash = %s, full_name = %s, last_login = %s
                        WHERE user_id = %s;
                    """, (user.username, user.email, user.password_hash, user.full_name, user.last_login, user.user_id))
                    self.conn.commit()
                    return user
            cursor.execute("""
                INSERT INTO asgu.users (username, email, password_hash, full_name, created_at)
                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                RETURNING user_id, created_at;
            """, (user.username, user.email, user.password_hash, user.full_name))
            user_id, created_at = cursor.fetchone()
            self.conn.commit()
            return User(user_id=user_id, username=user.username, email=user.email,
                        password_hash=user.password_hash, full_name=user.full_name, created_at=created_at)

    def delete_user(self, user: User):
        """Удаляет пользователя по user_id."""
        with self.conn.cursor() as cursor:
            cursor.execute("DELETE FROM asgu.users WHERE user_id = %s;", (user.user_id,))
            self.conn.commit()

    def get_user(self, user_id: int) -> Optional[User]:
        """Возвращает информацию о конкретном пользователе по user_id."""
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT * FROM asgu.users WHERE user_id = %s;", (user_id,))
            result = cursor.fetchone()
            if result:
                return User(*result)
            return None

    def get_user_list(self) -> List[User]:
        """Возвращает список всех пользователей с полями `full_name` и `username` для отображения в интерфейсе."""
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT user_id, full_name, username FROM asgu.users;")
            results = cursor.fetchall()
            return [User(user_id=row[0], full_name=row[1], username=row[2], email="", password_hash="") for row in results]
