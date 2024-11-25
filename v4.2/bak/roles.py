import psycopg2
from dataclasses import dataclass

@dataclass
class UserRole:
    userId: int
    role: str

@dataclass
class RoleCommand:
    role: str
    command: str

class RoleManagement:
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
    		self.conn.autocommit = True

    def getUserRoles(self, userId: int):
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT role FROM UserRoles WHERE user_id = %s", (userId,))
            roles = cursor.fetchall()
        return [role[0] for role in roles]

    def addUserRole(self, userRole: UserRole):
        with self.conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO UserRoles (user_id, role) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (userRole.userId, userRole.role)
            )

    def removeUserRole(self, userRole: UserRole):
        with self.conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM UserRoles WHERE user_id = %s AND role = %s",
                (userRole.userId, userRole.role)
            )

    def checkCommandPermission(self, userId: int, command: str):
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
                (userId, command)
            )
            result = cursor.fetchone()[0]
        return result
