from dataclasses import dataclass

@dataclass 
class Host:
	Random: bytes
	UserHash: bytes
	IP: str         #15 bytes
	Host: str
	AppName: str	#10 bytes
	AppVersion: str #5 bytes
	CertVersion: str   #10 bytes
	DHCert: bytes  # 48 bytes????


@dataclass 
class Hello:
	Encryption: bytes          #15 bytes
	Encrypted: Host         #15 bytes
	Signature: bytes



@dataclass 
class pkt:
	source: str
	target: str
	ptype: str
	enc: str
	seq: int
	message: bytes


