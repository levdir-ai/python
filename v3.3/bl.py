from datetime import datetime, timedelta
from cls.blacklist import IPBlacklist

Blacklist=IPBlacklist()
# Simulate failed login attempts
Blacklist.DecreaseReputation("192.168.1.1")
Blacklist.DecreaseReputation("192.168.1.1")
Blacklist.DecreaseReputation("192.168.1.1")  # Should trigger blacklist

# Check if blacklisted
print("Is blacklisted:", Blacklist.IsBlacklisted("192.168.1.1"))

# Remove from blacklist and reset reputation
Blacklist.ResetReputation("192.168.1.1")
print("Is blacklisted:", Blacklist.IsBlacklisted("192.168.1.1"))
