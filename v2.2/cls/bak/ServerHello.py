from dataclasses import dataclass

# The server hello includes the server’s certificate, digital signature,
# server random, and chosen cipher suite.

#DNSName:
#IP:
#Port:
#AppName:
#AppVersion:
#DHCert:
#ServerCertVesion:
#Random:
#Signature:
#=== Signature verify

@dataclass 
class ServerHello:
	DNSName: str
	IP: str         #15 bytes
	Port: str
	AppName: str	#10 bytes
	AppVersion: str #5 bytes
	CertVersion: str   #10 bytes
	DHCert: bytes  # 48 bytes????
	Random: bytes
	Signature: bytes
