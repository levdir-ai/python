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

    p= pkt("1","1","CHello1","PubKey,SYM", 1,s)
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
	    	senc.pass2key(ss.Encrypted.Random.hex()+shared_key.hex()+CliRandom.hex())
	    	print("Shared_key:\n",shared_key.hex())
	    	smsg=b" "

	    	print("\nStart at:",stime:=time.time())
	    	dlen=0
	    	for x in range(5):
	    		p= pkt("1","1","Data","DHSYM", 1,(str(x)+":Hello :"+os.urandom(32).hex()*1000 + ":End").encode('latin-1'))
	    		sct.sendall(tt:=sckt.build(p,senc))
	    		dlen=dlen+len(tt)
	    	print("\nEnd at:",etime:=time.time()," Duration:",etime-stime ," Size KBytes:",dlen/1024)


	    	while smsg!=b'':
		    	smsg=input("\nEnter message to send. Enter to Exit:").encode('latin-1')
		    	#print("Send Data msg:",smsg)

#		    	p= pkt("1","1","Data","DHSYM", 1,smsg)
		    	p= pkt("1","1","Data","DHSYM", 1,smsg)
		    	sct.sendall(sckt.build(p,senc))
#		    	sct.sendall(sckt.build(p))

    	else:
	    	print("Signature verification Failed")

    if data.ptype=="Error":
    	print("\nGot Error from server:", data.message.decode('latin-1'))	
