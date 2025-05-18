import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

@dataclass
class User:
    user_id: Optional[int]
    username: str
    email: str
    password_hash: str
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    full_name: Optional[str] = ""



class UserManager:
    def __init__(self, db_path):
        try:
            self.conn = sqlite3.connect("asgu.db")
            self.conn.execute("PRAGMA foreign_keys = ON;")  # Включаем поддержку внешних ключей
            self.conn.row_factory = sqlite3.Row  # Делаем возврат в виде словаря
        except sqlite3.Error as e:
            print(f"Ошибка подключения: {e}")
            self.conn = None

    def CmdList(self):
        return list(filter(lambda x: x[:2]!='__', dir(self)))

    def IsReady(self):
        return self.conn is not None

    def Close(self):
        if self.conn:
            self.conn.close()

    def Validate(self, UserName, Hsh) -> Optional[User]:
        with self.conn:
            cursor = self.conn.execute(
                "SELECT * FROM users WHERE username = ? AND password_hash = ?;",
                (UserName, Hsh)
            )
            result = cursor.fetchone()
            if result:
                self.conn.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ? AND password_hash = ?;",
                    (UserName, Hsh)
                )
                return User(*result)
        return None

    def Save(self, user: User):
        with self.conn:
            cursor = self.conn.execute(
                "SELECT 1 FROM users WHERE user_id = ?;",
                (user.user_id,)
            )
            if cursor.fetchone():
                self.conn.execute(
                    """UPDATE users SET username = ?, email = ?, full_name = ?, last_login = ? 
                       WHERE user_id = ?;""",
                    (user.username, user.email, user.full_name, user.last_login, user.user_id)
                )
                return user
            cursor = self.conn.execute(
                """INSERT INTO users (username, email, password_hash, full_name, created_at) 
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);""",
                (user.username, user.email, user.password_hash, user.full_name)
            )
            user_id = cursor.lastrowid
            return User(user_id=user_id, username=user.username, email=user.email,
                        password_hash=user.password_hash, full_name=user.full_name,
                        created_at=datetime.now())

    def Delete(self, UserId):
        with self.conn:
            self.conn.execute("DELETE FROM users WHERE user_id = ?;", (UserId,))

    def Get(self, UserId: int) -> Optional[User]:
        with self.conn:
            cursor = self.conn.execute(
                "SELECT user_id, username, email, '', created_at, last_login, full_name FROM users WHERE user_id = ?;",
                (UserId,)
            )
            result = cursor.fetchone()
            if result:
                return User(*result)
        return None

    def GetList(self) -> List[User]:
        with self.conn:
            cursor = self.conn.execute("SELECT user_id, full_name, username, last_login FROM users;")
            return [User(user_id=row["user_id"], full_name=row["full_name"], username=row["username"],
                         last_login=row["last_login"], email="", password_hash="") for row in cursor.fetchall()]

    def GetUserRoles(self, UserId):
        with self.conn:
            cursor = self.conn.execute("SELECT role FROM UserRoles WHERE user_id = ?;", (UserId,))
            return [row["role"] for row in cursor.fetchall()]

    def AddUserRole(self, UserId, UserRole):
        with self.conn:
            self.conn.execute(
                "INSERT INTO UserRoles (user_id, role) VALUES (?, ?);",
                (UserId, UserRole)
            )

    def RemoveUserRole(self, UserId, UserRole):
        with self.conn:
            self.conn.execute(
                "DELETE FROM UserRoles WHERE user_id = ? AND role = ?;",
                (UserId, UserRole)
            )

    def IsCommandAllowed(self, UserId, Command):
        ClassName = Command.split('.')[0]
        with self.conn:
            cursor = self.conn.execute(
                """SELECT EXISTS (
                    SELECT 1 FROM UserRoles ur
                    JOIN RoleCommands rc ON ur.role = rc.role
                    WHERE ur.user_id = ? AND rc.command IN (?, ?)
                );""",
                (UserId, Command, ClassName + '.ALL')
            )
            return cursor.fetchone()[0]

    def SaveMe(self, user: User, MyUserId):
        return self.Save(user)

    def GetMe(self, MyUserId: int) -> Optional[User]:
        return self.Get(MyUserId)

    def GetMyRoles(self, MyUserId):
        return self.GetUserRoles(MyUserId)
