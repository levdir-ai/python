#import logging
#logger = logging.getLogger(__name__)

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


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server


#logging.basicConfig(filename='log/asguclient.log', level=logging.INFO, format='%(asctime)s: %(levelname)s:%(module)s.%(funcName)s: %(message)s')
#console_handler = logging.StreamHandler()
#logger.addHandler(console_handler)


print("Init ASYM Encryption")
mmenc=asymenc("cfg/pubkey.pem","")
print("	ENC ready:",mmenc.EncReady())
print("	DEC ready:",mmenc.DecReady())

print("Init SYM Encryption")
senc=symenc()
print("	Ready:",senc.Ready())
print("Init DHE Encryption")
d=dhe()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
	try:
		sct.connect((HOST, PORT))
	except:
		print("Can't connect to:",HOST,":",PORT,"\nExit.")
		exit()

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
	s.Encrypted=senc.encrypt(s.Encrypted)
	s.Encryption=mmenc.encrypt(s.Encryption) #[10:] # broke the encrypted message

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
			smsg=b" "
			print("SRV:",ss.Encrypted.Host,ss.Encrypted.Port, ss.Encrypted.IP)

# Load testing. Send 30MB of data
			print("\nStart at:",stime:=time.time())
			dlen=0
			for x in range(5):
				p= pkt("1","1","Data","DHSYM", 1,(str(x)+":Hello :"+os.urandom(32).hex()*1000 + ":End").encode('latin-1'))
				sct.sendall(tt:=sckt.build(p,senc))
#				sct.sendall(tt:=sckt.build(p))
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
