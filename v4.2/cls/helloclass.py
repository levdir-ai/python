import logging
logger = logging.getLogger("main")

import socket
import time
import os
import hashlib, uuid
import base64

from cls.typeclass import pkt,Hello,Host,cmd
from cls.scktclass import sckt

from cls.asymencclass import asymenc
from cls.symencclass import symenc
from cls.dheclass import dhe 

class DHEHello:
	def Client(sct,usr,passw,keyfile):
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
				return senc, ""
			else:
				#print("Signature verification Failed")
				return None, b'Signature verification Failed'
		else:
			#print("\nGot ERR from server",data)	
			return None, data.message			

	def Server(UMgr, SymEnc, KeyFile, ClientHelloMsg):
		# Init DHE
		DHE=dhe()
		# Init ASYM
		AsymEnc=asymenc("",KeyFile)
					
		DHE.GenerateKeys()
		ClientHelloMsg.Encryption=AsymEnc.Decrypt(ClientHelloMsg.Encryption)
		logger.debug("		Decrypt:%s",ClientHelloMsg.Encryption)
		if ClientHelloMsg.Encryption==-1: 
			logger.warning("		Client validation by Public Key failed! Invalid Public Key! Exit.")
			return -1,None,None
		else: 
			logger.info("		Client validation by Public Key successful!") 				

		SymEnc.Pass2Key(ClientHelloMsg.Encryption)
		ClientHelloMsg.Encrypted=SymEnc.Decrypt(ClientHelloMsg.Encrypted)
		logger.info("		Got Client DHE certificate.")
#		       				print("User Password hash:",ClientHelloMsg.Encrypted.UserHash)
		
		Usr=UMgr.Validate(ClientHelloMsg.Encrypted.User,ClientHelloMsg.Encrypted.PHash)
		if Usr is None:
			logger.error("		Password incorrect for user:" + str(ClientHelloMsg.Encrypted.User))
			return -2,None,None

		k=DHE.Exchange(DHE.PublicKeyImp(ClientHelloMsg.Encrypted.DHCert))
		logger.info("		Shared_Key:%s....%s",k.hex()[:10],k.hex()[-10:])
		SymEnc.Pass2Key(k.hex())

		
		ServerHelloMsg=Hello(Encrypted=Host( 
				Random = os.urandom(16),
				User = ClientHelloMsg.Encrypted.User,
				PHash = b'',
				AppName ="ASGU",
				AppVersion ="1.0",
				CertVersion = "DHE",
				DHCert = DHE.GetPublicKeyExp(),
				IP=sckt.ip4_addresses(),
				Host=socket.gethostname(),
			),
			Encryption= b'None',
			Signature=b''
		)
		ServerHelloMsg.Signature=AsymEnc.Sign(ServerHelloMsg.Encrypted)
		SymEnc.Pass2Key(ServerHelloMsg.Encrypted.Random.hex()+k.hex()+ClientHelloMsg.Encrypted.Random.hex())

		return 0,ServerHelloMsg,Usr


# in case of -1 
#Blacklist.DecreaseReputation(address[0])
#p= pkt("1","1","Error","", 1,b'Invalid Public Key')
# await loop.sock_sendall(client, sckt.Build(p))
# continue


# in case of -2 
#Blacklist.DecreaseReputation(address[0])
# 			p= pkt("1","1","Error","", 1,b'Invalid User name / password')
#			UMgr.Close()
#			await loop.sock_sendall(client, sckt.Build(p))
			#continue


