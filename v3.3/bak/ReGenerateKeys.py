import socket
import time
import pickle
import os
import hashlib, uuid
import base64

from cls.typeclass import pkt,Hello,Host
from cls.scktclass import sckt

from cls.asymencclass import asymenc
from cls.symencclass import symenc
from cls.dheclass import dhe

#salt = uuid.uuid4().hex
#hashed_password = hashlib.sha512(password + salt).hexdigest()

#1. Client - ClientHello ->Server
#   PublicKey.encrypt (200 bytes)
#2. Server - ServerHello ->Client

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server

print("Init ASYM Encryption")
mmenc=asymenc("cfg/pubkey.pem","")
print("	ENC ready:",mmenc.EncReady())
print("	DEC ready:",mmenc.DecReady())

print("Init SYM Encryption")
senc=symenc()
print("	Ready:",senc.Ready())
print("Init DHE Encryption")
d=dhe()
d.GenerateKeys()


s=Hello(Encrypted=Host(
		Random = os.urandom(16),
		UserHash = b'Dir!QAZ@WSX',
		AppName ="ASGU",
		AppVersion ="1.0",
		CertVersion = "DHE",
		DHCert = b'',
		IP=sckt.ip4_addresses(),
		Host=socket.gethostname(),
		),
		Encryption= os.urandom(16).hex(),
		Signature=b''
	)

CliRandom=s.Encrypted.Random
senc.pass2key(s.Encryption)
s.Encrypted.DHCert=d.GetPublicKeyExp()

#print("Client CErt:",s.Encrypted.DHCert)
s.Encrypted=senc.encrypt(s.Encrypted)
#print("\n",s)
s.Encryption=mmenc.encrypt(s.Encryption) #[10:] # broke the encrypted message
#print("\n",s)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
	sct.connect((HOST, PORT))

	p= pkt("1","1","CHello","PubKey,SYM", 1,s)
	sct.sendall(sckt.build(p))

	data,sz = sckt.parse(sct.recv(10000))

#    print(f"Received {data.ptype!r}")
	if data.ptype=="SHello":
		print("\nGot Hello from server")
		ss=data.message
		print("Signature verification:",sign:=mmenc.verify(ss.Encrypted,ss.Signature))
#    	print("Server CErt:",ss.Encrypted.DHCert)
		if sign :
			shared_key =d.Exchange(d.PublicKeyImp(ss.Encrypted.DHCert))
			senc.pass2key(ss.Encrypted.Random.hex()+shared_key.hex()+CliRandom.hex())
			print("Shared_key:",shared_key.hex()[:10],"....",shared_key.hex()[-10:])
			smsg=b"Message 1, Shared key 1 "
			p= pkt("1","1","Data","DHSYM", 1,smsg)
			sct.sendall(sckt.build(p,senc))

		else:
			print("Signature verification Failed")

	print("\n\n\n ==== generate NEW keys ==========")
	smsg=b"\n\n============NEW KEYS======\n"
	p= pkt("1","1","Data","DHSYM", 1,smsg)
	sct.sendall(sckt.build(p,senc))

	d.GenerateKeys()

	s1=Hello(Encrypted=Host(
			Random = os.urandom(16),
			UserHash = b'Dir!QAZ@WSX',
			AppName ="ASGU",
			AppVersion ="1.0",
			CertVersion = "DHE",
			DHCert = b'',
			IP=sckt.ip4_addresses(),
			Host=socket.gethostname(),
			),
			Encryption= os.urandom(16).hex(),
		Signature=b''
		)

	CliRandom=s1.Encrypted.Random
	senc.pass2key(s1.Encryption)
	s1.Encrypted.DHCert=d.GetPublicKeyExp()
	s1.Encrypted=senc.encrypt(s1.Encrypted)
	s1.Encryption=mmenc.encrypt(s1.Encryption) #[10:] # broke the encrypted message
	p= pkt("1","1","CHello","PubKey,SYM", 1,s1)
	sct.sendall(sckt.build(p))

	data,sz = sckt.parse(sct.recv(10000))

#    print(f"Received {data.ptype!r}")
	if data.ptype=="SHello":
		print("\nGot Hello from server")
		ss=data.message
		print("Signature verification:",sign:=mmenc.verify(ss.Encrypted,ss.Signature))
#    	print("Server CErt:",ss.Encrypted.DHCert)
		if sign :
			shared_key =d.Exchange(d.PublicKeyImp(ss.Encrypted.DHCert))
			senc.pass2key(ss.Encrypted.Random.hex()+shared_key.hex()+CliRandom.hex())
			print("Shared_key:",shared_key.hex()[:10],"....",shared_key.hex()[-10:])
			smsg=b"Message 2, Shared key 2 "
			p= pkt("1","1","Data","DHSYM", 1,smsg)
			sct.sendall(sckt.build(p,senc))

		else:
			print("Signature verification Failed")

	if data.ptype=="Error":
		print("\nGot Error from server:", data.message.decode('latin-1'))
