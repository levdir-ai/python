# implementation of TLS like handshake
import logging
logger = logging.getLogger("main")

#Native library
import textwrap
import socket
import time
import os
import hashlib, uuid
import base64

#Custom library
from cls.typeclass import pkt,Hello,Host,cmd
from cls.scktclass import sckt

from cls.enc.asymencclass import asymenc
from cls.enc.symencclass import symenc
from cls.enc.dheclass import dhe 

class DHEHello:
#Client side
#socket, user str, passw str, keyfile str path to keyfile
# return initialized SYMENC object and in error case datamessage



	def Client(sct,SymEnc,usr,passw,keyfile):
		print("Init ASYM Encryption")
		AsymEnc=asymenc(keyfile,"")

		if not AsymEnc.EncReady():
#			print("	Public key error.")
			return b'		Public key error.'
					

		print("	ENC ready:",AsymEnc.EncReady())
		print("	DEC ready:",AsymEnc.DecReady())
	
		print("Init DHE Encryption")
		DheEnc=dhe()
		PassHsh=hashlib.sha512(passw.encode('utf-8')).hexdigest()
	
		DheEnc.GenerateKeys()

		#Encryption key for SYMEnc (Encrypted part of ClientHelloMsg)
		ClientEncryptionKey=os.urandom(16).hex()  
		CliRandom=os.urandom(16)

		ClientHelloMsg=Hello(Encrypted=Host(
				Random = CliRandom,
				User = usr,
				PHash = PassHsh,
				AppName ="ASGU",
				AppVersion ="1.0",
				CertVersion = "DHE",
				DHCert = DheEnc.GetPublicKeyExp(),
				IP=sckt.ip4_addresses(),
				Host=socket.gethostname(),
				),
			EncryptionKey= ClientEncryptionKey,
			Encryption= SymEnc.GetName(),
			Signature=b''
			)
		SymEnc.Pass2Key(ClientHelloMsg.EncryptionKey)
		print("		SYMEnc key:",ClientHelloMsg.EncryptionKey[:8]+"..."+ClientHelloMsg.EncryptionKey[-8:])
#		ClientHelloMsg.Encrypted.DHCert= DheEnc.GetPublicKeyExp()
		ClientHelloMsg.Encrypted=SymEnc.Encrypt(ClientHelloMsg.Encrypted)
		ClientHelloMsg.EncryptionKey=AsymEnc.Encrypt(ClientHelloMsg.EncryptionKey) #[10:] # broke the encrypted message
	
		p= pkt("1","1","CHello","NO", 1,ClientHelloMsg)
		sct.sendall(sckt.Build(p))
	
		data = sckt.Parse(sct.recv(10000))
	
		if data.ptype=="SHello":
			print("\nGot Hello from server")	
			ServerHelloMsg=data.message
			print("		Signature verification:",sign:=AsymEnc.Verify(ServerHelloMsg.Encrypted,ServerHelloMsg.Signature))
			if sign :
				#decrypt Server Hello with client secret (ClientEncryption) 
				SymEnc.Pass2Key(ClientEncryptionKey)
				ServerHelloMsg.Encrypted=SymEnc.Decrypt(ServerHelloMsg.Encrypted)

				DHESharedKey=DheEnc.Exchange(DheEnc.PublicKeyImp(ServerHelloMsg.Encrypted.DHCert))
 	
				print("		Shared key:",DHESharedKey.hex()[:10],"....",DHESharedKey.hex()[-10:])
				print("		SRV:",ServerHelloMsg.Encrypted.Host,ServerHelloMsg.Encrypted.Port,ServerHelloMsg.Encrypted.IP)
	
				SymEnc.Pass2Key(ServerHelloMsg.Encrypted.Random.hex()+DHESharedKey.hex()+CliRandom.hex())
				print("		DHSYM Encryption enabled.")
				return ""
			else:
				#print("Signature verification Failed")
				return b'		Signature verification Failed'
		else:
			#print("\nGot ERR from server",data)	
			return data.message	

	def GetEncryption(ClientHelloMsg):
		return ClientHelloMsg.Encryption

# Server side Hello
# UserManager (DBL class) object SYMENC initialized object, KeyFile str path to private keyfile, Data message 
# return error int, Server Hello datamessage, Usr object
	def Server(UMgr, SymEnc, KeyFile, ClientHelloMsg):
		# Init DHE

		DHE=dhe()
		DHE.GenerateKeys()

		# Init ASYM
		AsymEnc=asymenc("",KeyFile)
		if not AsymEnc.DecReady():
			print("	Private key error. Exit.")
			return -3,None,None
					
		ClientHelloMsg.EncryptionKey=AsymEnc.Decrypt(ClientHelloMsg.EncryptionKey)
		logger.info("		SYMEnc key:%s",ClientHelloMsg.EncryptionKey[:8]+"..."+ClientHelloMsg.EncryptionKey[-8:])
		if ClientHelloMsg.EncryptionKey==-1: 
			logger.warning("		Client validation by Public Key failed! Invalid Public Key or encryption method! Exit.")
			return -1,None,None
		else: 
			logger.info("		Client validation by Public Key successful!") 				

		SymEnc.Pass2Key(ClientHelloMsg.EncryptionKey)
		ClientHelloMsg.Encrypted=SymEnc.Decrypt(ClientHelloMsg.Encrypted)
		logger.debug("	CHello (unencrypted):\n"+textwrap.indent( textwrap.fill(str(ClientHelloMsg), width=80), ' '*16) +"\n") 	

		logger.info("		Got Client DHE certificate.")
		
		Usr=UMgr.Validate(ClientHelloMsg.Encrypted.User,ClientHelloMsg.Encrypted.PHash)
		if Usr is None:
			logger.error("		Password incorrect for user:" + str(ClientHelloMsg.Encrypted.User))
			return -2,None,None

		CliRandom=ClientHelloMsg.Encrypted.Random
		SrvRandom=os.urandom(16)		

		ServerHelloMsg=Hello(Encrypted=Host( 
				Random = SrvRandom,
				User = ClientHelloMsg.Encrypted.User,
				PHash = b'',
				AppName ="ASGU",
				AppVersion ="1.0",
				CertVersion = "DHE",
				DHCert = DHE.GetPublicKeyExp(),
				IP=sckt.ip4_addresses(),
				Host=socket.gethostname(),
			),
			EncryptionKey= b'',
			Encryption= SymEnc.GetName(),
			Signature=b''
		)

		logger.debug("	SHello (unencrypted):\n"+textwrap.indent( textwrap.fill(str(ServerHelloMsg), width=80), ' '*16) +"\n") 	

#=======        Encrypt ServerHelloMsg.Encrypted with the Client secret (ClientHelloMsg.Encryption)
		SymEnc.Pass2Key(ClientHelloMsg.EncryptionKey)
		ServerHelloMsg.Encrypted=SymEnc.Encrypt(ServerHelloMsg.Encrypted)

#==========     Sign ServerHello with private key
		ServerHelloMsg.Signature=AsymEnc.Sign(ServerHelloMsg.Encrypted)

		DHESharedKey=DHE.Exchange(DHE.PublicKeyImp(ClientHelloMsg.Encrypted.DHCert))
		logger.info("		Shared_Key:%s....%s",DHESharedKey.hex()[:10],DHESharedKey.hex()[-10:])

		SymEnc.Pass2Key(SrvRandom.hex()+DHESharedKey.hex()+CliRandom.hex())
		logger.info("		DHSYM Encryption enabled.")
		return 0,ServerHelloMsg,Usr

