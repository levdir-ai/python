#import logging
#logger = logging.getLogger(__name__)

import socket
import time
import pickle
import os
import hashlib, uuid
import base64
import psycopg2


from cls.typeclass import pkt,Hello,Host,cmd
from cls.scktclass import sckt

from cls.asymencclass import asymenc
from cls.symencclass import symenc
from cls.dheclass import dhe 
#from cls.cmdcliclassc import ProcessCmd 


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server



#logging.basicConfig(filename='log/asguclient.log', level=logging.INFO, format='%(asctime)s: %(levelname)s:%(module)s.%(funcName)s: %(message)s')
#console_handler = logging.StreamHandler()
#logger.addHandler(console_handler)

def SHello(sct,usr,passw,keyfile):
	print("Init ASYM Encryption")
	mmenc=asymenc(keyfile,"")
	print("	ENC ready:",mmenc.EncReady())
	print("	DEC ready:",mmenc.DecReady())

	print("Init SYM Encryption")
	senc=symenc()
	print("	Ready:",senc.Ready())
	print("Init DHE Encryption")
	d=dhe()
	ppwd=hashlib.sha512(passw.encode('latin-1')).hexdigest()

	d.GenerateKeys()
	s=Hello(Encrypted=Host(
			Random = os.urandom(16),
			User = usr,
			PHash = ppwd,
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
	senc.Pass2Key(s.Encryption)
	s.Encrypted.DHCert=d.GetPublicKeyExp()
	s.Encrypted=senc.Encrypt(s.Encrypted)
	s.Encryption=mmenc.Encrypt(s.Encryption) #[10:] # broke the encrypted message

	p= pkt("1","1","CHello","PubKey,SYM", 1,s)
	sct.sendall(sckt.Build(p))

	data,sz = sckt.Parse(sct.recv(10000))

	if data.ptype=="SHello":
		print("\nGot Hello from server")	
		ss=data.message
		print("Signature verification:",sign:=mmenc.Verify(ss.Encrypted,ss.Signature))
		if sign :
			shared_key=d.Exchange(d.PublicKeyImp(ss.Encrypted.DHCert))

			print("Shared_key:",shared_key.hex()[:10],"....",shared_key.hex()[-10:])
			print("SRV:",ss.Encrypted.Host,ss.Encrypted.Port, ss.Encrypted.IP)

			senc.Pass2Key(ss.Encrypted.Random.hex()+shared_key.hex()+CliRandom.hex())
			return senc
		else:
			print("Signature verification Failed")
			return None


#==================================== MAIN ===============================
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
	try:
		sct.connect((HOST, PORT))
	except:
		print("Can't connect to:",HOST,":",PORT,"\nExit.")
		exit()

	usr=input("Enter user name (dir):")
	if usr=="": usr="dir"
	passw=input("Enter password:")

	senc=SHello(sct,usr,passw,"cfg/pubkey.pem")	
	smsg=b" "

	while smsg!="":
		smsg=input("\nEnter command to send. Enter to Exit:")
		cm=cmd(smsg,usr,{"UserId":"2","Command":"GetList"})
		p= pkt("1","1","CMD","DHSYM", 1,cm)
		sct.sendall(tt:=sckt.Build(p,senc))

		data,sz = sckt.Parse(sct.recv(60000))

		print(f"Received {data.ptype!r}", data.message)

	if data.ptype=="Error":
		print("\nGot Error from server:", data.message.decode('latin-1'))	
