import array
import jsonpickle
import logging
import os
import socket
import sys
import textwrap

from cls.typeclass import pkt
from cls.enc.symencchaclass import symenccha
from cls.enc.symencclass import symenc

logger = logging.getLogger("main")

# Class for processing Pkt's. Encrypt, decrypt etc.
#class pkt:
#	source: str - source internal address
#	target: str
#	ptype: str  - pocket type
#	enc: str    - encryption type  ASYM, DHE, DHSYM (SYM + DHE shared key) + combination of them
#	seq: int    - pocket seq
#	message: bytes  - data


class sckt:

#Build bytes arrray from PKT. 
#Input: PKT, encryption provider. In most cases SYM with DHE shared key
#return bytes array

	def Build(obj: pkt, enc=""):
		obj.seq=int(os.urandom(2).hex(),16)

		logger.debug("	Build: Message (unencrypted):\n" + textwrap.indent( textwrap.fill(jsonpickle.dumps(obj), width=80),' '*16))

		if obj.enc!="" and obj.enc!="NO":
			obj.source=sckt.ip4_addresses()
			if obj.enc=="SYMAES":
				obj.enc="SYMAES"
				# Add OK at the beginning, for decryption validation
				obj.message=enc.Encrypt(b'OK'+jsonpickle.dumps(obj.message).encode('utf-8')) 
			if obj.enc=="SYMCHA":
				obj.enc="SYMCHA"
				hd={"source":obj.source,"target": obj.target,"ptype":obj.ptype,"enc": obj.enc,"seq": obj.seq}
				obj.message=enc.Encrypt(jsonpickle.dumps(obj.message).encode('utf-8'), jsonpickle.dumps(hd).encode('utf-8')) 
		else: 
			if obj.enc!="NO": logger.warning("WARNING!!!!: UnEncrypted message sent:" + str(obj.message)[:50])


#		logger.info("	Build: Message (encrypted):\n"+textwrap.indent( textwrap.fill(str(obj.message), width=80), ' '*16) +"\n")

		s=jsonpickle.dumps(obj).encode('utf-8')	
		size=len(s)+4+3+3 # data + size+ PKT + END

		#Add start string b'PKT', size (4 bytes), encrypted DATA, end string b'END'
		ss=b'PKT'+size.to_bytes(4,'big')+s+b'END'
		logger.debug("	Build: PKT (encrypted):Size:"+str(len(ss))+"\n"+textwrap.indent( textwrap.fill(str(ss), width=80), ' '*16) +"\n")
		return ss

#Build PKT from bytes array. Reverse to Build
#Input Bytes, Encryption provider (DHSYM=DHE+ SYM)
#return PKT size.

	def Parse(obj ,enc=""):
		if len(obj)<10 : # Less than 10 bytes message, impossible (b'PKTssDataEND')
			return b'ERR' #,-1

		if obj[:3].decode('utf-8') != "PKT" : #Not PKT
			return b'ERR'#,-2

		size= int.from_bytes(obj[3:7],'big') # PKT size

		if size>len(obj) : #Compare data size (obj) + PKT size. 
			logger.error("ERROR:Sckt.parse: Data to small! Size:",size," Len:",len(obj),"\n")			
			return b'ERR'#,-3
		logger.debug("	Parse: PKT (encrypted):Size:"+str(len(obj))+"\n"+textwrap.indent( textwrap.fill(str(obj), width=80), ' '*16))

		p = jsonpickle.loads(obj[7:size-3].decode('utf-8')) # Convert data from 5 byte (PKTssData) to object
		if p.enc!="" and enc!="":
			if p.enc=="SYMAES": 
				s=enc.Decrypt(p.message)
				#ERR- decryption ERR (exception in Decrypt).
				#OK - first 2 bytes of correct message (Build method)
				if s[:3]==b'ERR' or s[:2]!=b'OK': 
#					print("DHSYM: Error decrypting!!!")
					p.message=b'ERR'
				else: 
					p.message=jsonpickle.loads(s[2:].decode('utf-8'))

			if p.enc=="SYMCHA": 
				hd={"source":p.source,"target": p.target,"ptype":p.ptype,"enc": p.enc,"seq": p.seq}
				try:
					s=enc.Decrypt(p.message, jsonpickle.dumps(hd).encode('utf-8'))
				except cryptography.exceptions.InvalidTag:
					p.message=b'ERR'
				except :
					p.message=b'ERR'
				else :
					p.message=jsonpickle.loads(s.decode('utf-8'))
		logger.debug("	Parse: Message (unencrypted):\n" + textwrap.indent( textwrap.fill(jsonpickle.dumps(p), width=80),' '*16)+"\n")
		return p

	def Size(obj: pkt):
		if len(obj)<10 : 
			return 0
		if obj[:3].decode('utf-8') != "PKT" : 
			return 0
		return int.from_bytes(obj[3:7],'big') #int(obj[4])+int(obj[3])*256

	def ip4_addresses():
	    return socket.gethostbyname(socket.gethostname())
