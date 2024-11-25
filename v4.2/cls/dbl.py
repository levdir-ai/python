import psycopg2
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from cls.typeclass import ConnectionParam

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
    def __init__(self, conn):
    	try:
    		conn = psycopg2.connect(
    			dbname=conn.dbname,
    			user=conn.user,
    			password=conn.password,
    			host=conn.host
	    	)
    	except:
    		self.conn = ""
    	else:
    		self.conn = conn

    def Close(self):
        if self.conn!="" : self.conn.close()

    def Validate(self, UserName, Hsh) -> Optional[User]:
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT * FROM asgu.users WHERE username = %s and password_hash = %s;", (UserName,Hsh))
            result = cursor.fetchone()
            if result:
            	with self.conn.cursor() as cursor1:
            		cursor1.execute("""
            			UPDATE asgu.users 
                		SET last_login = now()
                		WHERE username = %s and password_hash = %s;
                		""", (UserName,Hsh))
            		self.conn.commit()
            	return User(*result)
            return None

#Save or create user
    def Save(self, user: User):
        """Создает нового пользователя или обновляет существующего."""
        with self.conn.cursor() as cursor:
            if user.user_id:
                cursor.execute("""
                    SELECT 1 FROM asgu.users WHERE user_id = %s;
                """, (user.user_id,))
                if cursor.fetchone():
                    cursor.execute("""
                        UPDATE asgu.users 
                        SET username = %s, email = %s, full_name = %s, last_login = %s
                        WHERE user_id = %s;
                    """, (user.username, user.email, user.full_name, user.last_login, user.user_id))
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

    def Delete(self, UserId):
        """Удаляет пользователя по user_id."""
        with self.conn.cursor() as cursor:
            cursor.execute("DELETE FROM asgu.users WHERE user_id = %s;", (user.UserId,))
            self.conn.commit()

    def Get(self, UserId: int) -> Optional[User]:
        """Возвращает информацию о конкретном пользователе по UserId."""
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT   user_id, username, email,'',created_at, last_login,full_name FROM asgu.users WHERE user_id = %s;", (UserId,))
            result = cursor.fetchone()
            if result:
                return User(*result)
            return None

    def GetList(self) -> List[User]:
        """Возвращает список всех пользователей с полями `full_name` и `username` для отображения в интерфейсе."""
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT user_id, full_name, username , last_login FROM asgu.users;")
            results = cursor.fetchall()
            return [User(user_id=row[0], full_name=row[1], username=row[2], last_login=row[3], email="", password_hash="") for row in results]



#User roles managment

    def GetUserRoles(self, UserId):
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT role FROM UserRoles WHERE user_id = %s", (UserId,))
            roles = cursor.fetchall()
        return [role[0] for role in roles]

    def AddUserRole(self,UserId, UserRole):
        with self.conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO UserRoles (user_id, role) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (UserId, UserRole)
            )

    def RemoveUserRole(self, UserId, UserRole):
        with self.conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM UserRoles WHERE user_id = %s AND role = %s",
                (UserId, UserRole)
            )

    def IsCommandAllowed(self, UserId,Command):
#        tCmd=type(Class).__name__+'.'+Command
        tCmd=Command
#        print("CMD:", tCmd)
        with self.conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT 1 
                    FROM UserRoles ur
                    JOIN RoleCommands rc ON ur.role = rc.role
                    WHERE ur.user_id = %s AND rc.command = %s
                )
                """,
                (UserId, tCmd)
            )
            result = cursor.fetchone()[0]
        return result

    def Test(self, UserId,Command):
       
        return "Test:"+str(UserId)+":"+Command
