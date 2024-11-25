import psycopg2
from cls.dbl import UserManager, User
from cls.typeclass import pkt,Hello,Host,cmd, ConnectionParam


cnn = ConnectionParam(
    dbname="postgres",
    user="asgu",
    password="asgu",
    host="localhost"
)

usr= User(
	user_id = -1,
	username="dir5",
	email="i5@i.am",
	password_hash = "asfasd",
	full_name = "Michel Dir5"
	)

user_manager = UserManager(cnn)

#new_user = user_manager.Save(usr)
#print(new_user)

#usr.email="new_email@example.com"
#usr.user_id=1
#user_manager.Save(usr)
#pp='4b0ab7b94e92a4f175774a4ad8a9a8c4d273671086ef091a689d63d3752a53ba043a1daf6204c9d4043b24bb42e18903029b43acd5efeabf7f368c26d532ab6e'
for u in user_manager.GetList():
	print("User:",u.username, "Full Name:",u.full_name)

user_manager.Close()
