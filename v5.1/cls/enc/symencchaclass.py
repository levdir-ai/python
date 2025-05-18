import logging
logger = logging.getLogger("main")

import os
import jsonpickle

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class symenccha:
	def __init__(self):
		logger.info("		Init SYMCHA")
		self.salt=b'Some pepper!!!!'
		self.key=""


	def GetName(self):
		return "SYMCHA"
#pastxt string

	def Pass2Key(self, pastxt):
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=self.salt,
			iterations=480000,
		)
		self.key = kdf.derive(bytes(pastxt,'utf-8'))

	def GetKey(self):
		return self.key

	def SetKey(self,Key):
		self.key=Key

	def Ready(self):
		return self.key != ""


	def Encrypt(self, data, tag=b'Empty Tag'):   # return iv 16bytes + encrypted data
		chacha=ChaCha20Poly1305(self.key)
		data=jsonpickle.dumps(data).encode('utf-8')
		nonce = os.urandom(12)
		ct = chacha.encrypt(nonce, data, tag)
		ct=nonce+ct
		return (ct)

	def Decrypt(self, data, tag=b'Empty Tag'):   # text= iv 16bytes + encrypted data
		try:
			nonce=data[:12] 
			chacha=ChaCha20Poly1305(self.key)
			data=chacha.decrypt(nonce, data[12:]  , tag)
		except:
			return b'ERR'
		else:
			return jsonpickle.loads(data.decode('utf-8'))

