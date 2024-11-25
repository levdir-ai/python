from dataclasses import dataclass
from typing import Optional

#Host description
@dataclass 
class Host:
	Random: bytes #random for the secret
	User: bytes #username
	PHash: bytes #password hash
	IP: str         #15 bytes
	Host: str       #host name
	CertVersion: str   #10 bytes "DHE"
	DHCert: bytes  # certificat body
	AppName : Optional[str] = "ASGU" #str #10 bytes "ASGU"
	AppVersion: Optional[str] = "1.0" #5 bytes
	Port : Optional[int] = 15555

#Hello data structure
@dataclass 
class Hello:
	Encryption: bytes          #Encryption key for PubKey+SYM encryption. Encrypted with public key
	Encrypted: Host         #Encrypted part of message (SYM method)
	Signature: bytes  #Signature with private key. No encryption

#pocket 
@dataclass 
class pkt:
	source: str
	target: str
	ptype: str
	enc: str
	seq: int
	message: bytes

@dataclass 
class cmd:
	cmd: str
	user: str
	data: bytes

@dataclass 
class ConnectionParam:
    dbname : str
    user : str
    password : str
    host : str
