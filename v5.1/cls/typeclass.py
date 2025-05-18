from dataclasses import dataclass
from typing import Optional, Dict

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

#Hello data structure (TLS handshake like)
@dataclass 
class Hello:
	EncryptionKey: bytes          #Encryption key for PubKey+SYM encryption. Encrypted with public key
	Encrypted: Host         #Encrypted part of message (SYM method)
	Signature: bytes  #Signature with private key. No encryption
	Encryption: Optional [str] = "SYMAES"          #Encryption key for PubKey+SYM encryption. Encrypted with public key

#pocket. Transport level
@dataclass 
class pkt:
	source: str
	target: str
	ptype: str
	enc: str
	seq: int
	message: bytes

#Command structure
@dataclass 
class cmd:
	cmd: str    #Command
	user: str   #user name called command
	args: Dict[str, any] #Command params (dictionary)

# Database connection params
@dataclass 
class ConnectionParam:
    dbname : str
    user : str
    password : str
    host : str
