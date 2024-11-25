import psycopg2
from cls.dbl import UserManager, User
from cls.typeclass import pkt,Hello,Host,cmd, ConnectionParam

def call_method(o, name):
    return getattr(o, name)()

def IsValidMethod(MyClass,MethodName):
	method_list = []
	for attribute in dir(MyClass):
	    attribute_value = getattr(MyClass, attribute)
	    # Check that it is callable
	    if callable(attribute_value):
       	 # Filter all dunder (__ prefix) methods
	    	if attribute.startswith('__') == False:
	            method_list.append(attribute)
	return MethodName in method_list

cnn = ConnectionParam(
    dbname="postgres",
    user="asgu",
    password="asgu",
    host="localhost"
)



# Assuming 'UserRoleManager' is imported and already connected to your PostgreSQL database.

# Initialize the UserRoleManager class
manager = UserManager(cnn)

print("\nMethod List:",MList:=IsValidMethod(manager,"GetList"))

aa=call_method(manager, "GetList") 
print("\nGetList:",aa)

 
# Test data: User ID 1 should be an Admin, User ID 2 should be UserRO, and User ID 3 should be UserRW.

# Example 1: Get roles for a user (e.g., User ID 1)
user_id = 2
user_roles = manager.GetUserRoles(user_id)
print(f"Roles for user {user_id}: {user_roles}")

command_to_check = "GetList"
is_allowed = manager.IsCommandAllowed(user_id, command_to_check)
print(f"Is command '{command_to_check}' available for user {user_id}? {is_allowed}")       ,

