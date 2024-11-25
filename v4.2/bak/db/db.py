import psycopg2
from dbl import UserManager, User

conn = psycopg2.connect(
    dbname="postgres",
    user="asgu",
    password="asgu",
    host="localhost"
)

usr= User(
	user_id = 1,
	username="dir",
	email="i@i.am",
	password_hash = "asfasd",
	full_name = "Michel Dir"
	)

user_manager = UserManager(conn)

new_user = user_manager.save_user(usr)
print(new_user)

usr.email="new_email@example.com"
usr.user_id=1
user_manager.save_user(usr)

print(user_manager.get_user_list())

conn.close()
