import os
#import array
import pickle
import sys
from netifaces import interfaces, ifaddresses, AF_INET

#import cls.typeclass 

class sckt:
	def __init__(self):
		self.salt=b'Some pepper!!!!'
		self.key=""

	def build(obj, enc=""):
		if obj.enc!="" and enc!="":
			#print("Ecryption enabled!")
			obj.message=enc.encrypt(obj.message)
		s=pickle.dumps(obj)	
		size=len(s)+2+3+3 # data + size+ PKT + END
		ss=b'PKT'+size.to_bytes(2,'big')+s+b'END'
		return ss

	def parse(obj,enc=""):
		if len(obj)<10 : 
			return b'',-1
		if obj[:3].decode('latin-1') != "PKT" : 
			return b'',-2
		size= int(obj[4])+int(obj[3])*256
		p = pickle.loads(obj[5:size])
		if p.enc!="" and enc!="":
			#print("Ecryption enabled! enc.type:",p.enc)
			if p.enc=="DHSYM": p.message=enc.decrypt(p.message)
		return p,size

	def ip4_addresses():
	    ip = []
	    for interface in interfaces():
	        for link in ifaddresses(interface)[AF_INET]:
	            ip.append(link['addr'])
	    return ip

	def gethostname():
	    return os.gethostname()



