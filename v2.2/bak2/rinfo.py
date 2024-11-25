import socket
from netifaces import interfaces, ifaddresses, AF_INET
import pickle
import os
from cls.ClientHello import ClientHello,Client
from cls.ServerHello import ServerHello
import hashlib, uuid
from cls.asymencclass import asymenc
from cls.symencclass import symenc
from cls.dheclass import dhe 

#salt = uuid.uuid4().hex
#hashed_password = hashlib.sha512(password + salt).hexdigest()

#1. Client - ClientHello ->Server 
#   PublicKey.encrypt (200 bytes)
#2. Server - ServerHello ->Client
def ip4_addresses():
    ip = []
    for interface in interfaces():
        for link in ifaddresses(interface)[AF_INET]:
            ip.append(link['addr'])
    return ip


print("Init Encryption")
        	

s=ClientHello(Encrypted=Client( 
		Random = os.urandom(16),
		UserHash = b'Dir!QAZ@WSX',
		AppName ="ASGU",
		AppVersion ="1.0",
		CertVersion = "DHE",
		DHCert = b'',
		IP=ip4_addresses()
		),
		Encryption= os.urandom(16).hex()
	)



mmenc=asymenc("cls/pubkey.pem","cls/privkey.pem")
print("Init Encryption\n")
print("ENC ready:",mmenc.EncReady())
print("DEC ready:",mmenc.DecReady())

print("Init SYM Encryption\n")
senc=symenc()

print("Init DHE Encryption\n")

d=dhe()
d.GenerateKeys()
print("Exp Pub Key\n")

with open("test.out", 'rb') as pem_in:
	pemlines = pem_in.read()
s=pickle.loads(pemlines)
print(s)
s.Encryption=mmenc.decrypt(s.Encryption)
print("\n",s)
senc.pass2key(s.Encryption)
s.Encrypted=senc.decrypt(s.Encrypted)
print("\n",s)

k=d.Exchange(d.PublicKeyImp(s.Encrypted.DHCert))
print("Key:",k.hex())
exit()


