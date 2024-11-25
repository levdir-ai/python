from dataclasses import dataclass

#Host description
@dataclass 
class Host:
	Random: bytes #random for the secret
	UserHash: bytes #username+userpassword hash
	IP: str         #15 bytes
	Port = 15555
	Host: str       #host name
	AppName : str #10 bytes "ASGU"
	AppVersion: str #5 bytes
	CertVersion: str   #10 bytes "DHE"
	DHCert: bytes  # certificat body


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
