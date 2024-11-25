import psycopg2
from cls.dbl import UserManager, User
from cls.typeclass import pkt,Hello,Host,cmd, ConnectionParam


cnn = ConnectionParam(
    dbname="postgres",
    user="asgu",
    password="asgu",
    host="localhost"
)

# Assuming 'UserRoleManager' is imported and already connected to your PostgreSQL database.

# Initialize the UserRoleManager class
manager = UserManager(cnn)

# Test data: User ID 1 should be an Admin, User ID 2 should be UserRO, and User ID 3 should be UserRW.

# Example 1: Get roles for a user (e.g., User ID 1)
user_id = 1
user_roles = manager.GetUserRoles(user_id)
print(f"Roles for user {user_id}: {user_roles}")

command_to_check = "CreateUser"
is_allowed = manager.IsCommandAllowed(user_id, command_to_check)
print(f"Is command '{command_to_check}' available for user {user_id}? {is_allowed}")       ,

new_role = "UserRW"
manager.AddUserRole(2, new_role)
print(f"Added role '{new_role}' to user 2.")

updated_roles = manager.GetUserRoles(2)
print(f"Updated roles for user 2: {updated_roles}")

manager.RemoveUserRole(2, "UserRO")
print("Removed role 'UserRO' from user 2.")

updated_roles_after_removal = manager.GetUserRoles(2)
print(f"Roles for user 2 after removal: {updated_roles_after_removal}")

is_allowed_post_update = manager.IsCommandAllowed(2, "EditProfile")
print(f"Is 'EditProfile' command available for user 2 after update? {is_allowed_post_update}")
