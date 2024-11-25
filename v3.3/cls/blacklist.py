from datetime import datetime, timedelta

class IPBlacklist:
    def __init__(self, InitialReputation=3, TimeoutMinutes=60):
        # Store IPs with a dictionary {IP: [Reputation, LastFailedAttempt]}
        self.IPs = {}
        self.InitialReputation = InitialReputation
        self.Timeout = timedelta(minutes=TimeoutMinutes)


    def DecreaseReputation(self, IP):
        #Decrease reputation on failed login attempt; blacklist if necessary.
        CurrentTime = datetime.now()
        # Reset reputation if last attempt was too long ago
        if IP in self.IPs:
            _, LastAttempt = self.IPs[IP]
            if CurrentTime - LastAttempt > self.Timeout:
                self.IPs[IP] = [self.InitialReputation, CurrentTime]

        # Decrease reputation or initialize it
        if IP not in self.IPs:
            self.IPs[IP] = [self.InitialReputation - 1, CurrentTime]
        else:
            self.IPs[IP][0] -= 1  # Decrease reputation
            self.IPs[IP][1] = CurrentTime  # Update last attempt time

        # Blacklist IP if reputation reaches 0
        if self.IPs[IP][0] <= 0:
#            self.Blacklist.add(IP)
            print(f"IP {IP} has been blacklisted.")

    def IsBlacklisted(self, IP):
        #Check if an IP is blacklisted.
        CurrentTime = datetime.now()
        if IP in self.IPs:
            Reputation, LastAttempt = self.IPs[IP]
            if CurrentTime - LastAttempt > self.Timeout:
                self.IPs[IP] = [self.InitialReputation, CurrentTime]
                return False
            else:
            	return Reputation<=0 
        else:
            return False

    def ResetReputation(self, IP):
        #Reset an IP's reputation if it's not blacklisted.
        if IP in self.IPs:
            self.IPs[IP] = [self.InitialReputation, datetime.now()]
            print(f"Reputation reset for IP {IP}.")

