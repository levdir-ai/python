import psycopg2
from cls.dbl import UserManager, User
from cls.typeclass import pkt,Hello,Host,cmd, ConnectionParam

def call_method(o, name):
    return getattr(o, name)()

cnn = ConnectionParam(
    dbname="postgres",
    user="asgu",
    password="asgu",
    host="localhost"
)



# Assuming 'UserRoleManager' is imported and already connected to your PostgreSQL database.

# Initialize the UserRoleManager class
manager = UserManager(cnn)


print("Type:", type(manager))
method_list = [method for method in dir(manager) if method.startswith('__') is False]
for i in  method_list:
	print("INSERT INTO asgu.rolecommands(\"role\", command) VALUES('Admin', 'UserManager." + str(i)+"');")

exit()

aa=call_method(manager, "GetList") 
print("\nGetList:",aa)

method_list = []
 
# attribute is a string representing the attribute name
MyClass=manager

for attribute in dir(MyClass):
    # Get the attribute value
    attribute_value = getattr(MyClass, attribute)
    # Check that it is callable
    if callable(attribute_value):
        # Filter all dunder (__ prefix) methods
        if attribute.startswith('__') == False:
            method_list.append(attribute)
 
print("\n Method list 2",method_list)


# Test data: User ID 1 should be an Admin, User ID 2 should be UserRO, and User ID 3 should be UserRW.

# Example 1: Get roles for a user (e.g., User ID 1)
user_id = 2
user_roles = manager.GetUserRoles(user_id)
print(f"Roles for user {user_id}: {user_roles}")

command_to_check = "GetList"
is_allowed = manager.IsCommandAllowed(user_id, command_to_check)
print(f"Is command '{command_to_check}' available for user {user_id}? {is_allowed}")       ,

