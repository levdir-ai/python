import socket
from netifaces import interfaces, ifaddresses, AF_INET
import pickle
import os
import hashlib, uuid
import base64

from cls.typeclass import pkt
from cls.scktclass import sckt

from cls.ClientHello import Hello,Host

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


s=ClientHello(Encrypted=Client( 
		Random = os.urandom(16),
		UserHash = b'Dir!QAZ@WSX',
		AppName ="ASGU",
		AppVersion ="1.0",
		CertVersion = "DHE",
		DHCert = b'',
		IP=ip4_addresses(),
		Host=socket.gethostname(),
		),
		Encryption= os.urandom(16).hex(),
		Signature=b''
	)

senc.pass2key(s.Encryption)
s.Encrypted.DHCert=d.GetPublicKeyExp()

#print("Client CErt:",s.Encrypted.DHCert)
#print("\nEnc Size:",len(pickle.dumps(s.Encrypted)))
#s.Encrypted=mmenc.encrypt(s.Encrypted)
#print("\n",s)

#print("\nENC:",pickle.dumps(s.Encrypted))
s.Encrypted=senc.encrypt(s.Encrypted)
#print("\n",s)
s.Encryption=mmenc.encrypt(s.Encryption) #[10:] # broke the encrypted message
#s.Encryption[10]=B'0'
#s.Encryption[11]=B'0'
#print("\nEnc Size:",len(pickle.dumps(s.Encrypted)))
#print("\nS Size:",len(pickle.dumps(s)))
#print("\n",s)

#with open("test.out", 'wb') as pem_out:
#	pem_out.write(pickle.dumps(s))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
    sct.connect((HOST, PORT))

    p= pkt("1","1","CHello1","PubKey", 1,s)
    sct.sendall(sckt.build(p))

    data,sz = sckt.parse(sct.recv(10000))

#    print(f"Received {data.ptype!r}")
    if data.ptype=="SHello1":
    	print("\nGot Hello1 from server")	
    	ss=data.message
    	print("Signature verification:",sign:=mmenc.verify(ss.Encrypted,ss.Signature))
#    	print("Server CErt:",ss.Encrypted.DHCert)
    	if sign :
	    	shared_key =d.Exchange(d.PublicKeyImp(ss.Encrypted.DHCert))
	    	senc.pass2key(shared_key.hex())
	    	print("Shared_key:\n",shared_key.hex())
	    	while 1==1:
		    	smsg=input("\nEnter message to send:").encode('latin-1')
		    	print("Send Data msg:")

		    	p= pkt("1","1","Data","DHSYM", 1,smsg)
		    	sct.sendall(sckt.build(p,senc))

    	else:
	    	print("Signature verification Failed")

    if data.ptype=="Error":
    	print("\nGot Error from server:", data.message.decode('latin-1'))	
