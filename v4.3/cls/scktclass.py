import logging
logger = logging.getLogger("main")
import socket
import os
import array
import pickle
import sys
from netifaces import interfaces, ifaddresses, AF_INET

#import cls.typeclass 

class sckt:
	def __init__(self):
		self.salt=b'Some salt!!!!'

	def Build(obj, enc=""):
		if obj.enc!="" and enc!="":
#			print("Ecryption enabled!")
			obj.message=enc.Encrypt(b'OK'+pickle.dumps(obj.message))
		s=pickle.dumps(obj)	
		size=len(s)+2+3+3 # data + size+ PKT + END
		ss=b'PKT'+size.to_bytes(2,'big')+s+b'END'
		return ss

	def Size(obj):
		if len(obj)<10 : 
			return 0
		if obj[:3].decode('latin-1') != "PKT" : 
			return 0
		return int(obj[4])+int(obj[3])*256

	def Parse(obj,enc=""):
		if len(obj)<10 : 
			return b'ERR',-1
		if obj[:3].decode('latin-1') != "PKT" : 
			return b'ERR',-2
		size= int(obj[4])+int(obj[3])*256
		if size>len(obj) : 
			print("ERROR:Sckt.parse: Data to small! Size:",size," Len:",len(obj),"\n")			
			return b'ERR',-3

		p = pickle.loads(obj[5:size])
		if p.enc!="" and enc!="":
#			print("Ecryption enabled! enc.type:",p.enc)
			if p.enc=="DHSYM": 
				s=enc.Decrypt(p.message)
#				print("S::",s)
				if s[:3]==b'ERR' or s[:2]!=b'OK': 
#					print("DHSYM: Error decrypting!!!")
					p.message=b'ERR'
				else: p.message=pickle.loads(s[2:])
		return p,size

	def ip4_addresses():
	    # ip = []
	    # for interface in interfaces():
	    #     for link in ifaddresses(interface)[AF_INET]:
	    #         ip.append(link['addr'])
	    return socket.gethostbyname(socket.gethostname())

