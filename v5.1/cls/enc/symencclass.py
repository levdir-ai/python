import logging
logger = logging.getLogger("main")

import os
import jsonpickle

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class symenc:
	def __init__(self):
		logger.info("		Init SYMAES")
		self.salt=b'Some pepper!!!!'
		self.key=""
		self.ClientRandom=b''
		self.ServerRandom=b''

	def GetName(self):
		return "SYMAES"


#pastxt - password in string f
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

#Tag only for unification (Cha encryption)
	def Encrypt(self, data,tag=""):   # return iv 16bytes + encrypted data
		padder = padding.PKCS7(128).padder()
		padded_data = padder.update(jsonpickle.dumps(data).encode('utf-8'))
		padded_data += padder.finalize()

		iv = os.urandom(16)
		cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
		encryptor = cipher.encryptor()
		ct = encryptor.update(padded_data) + encryptor.finalize()
		ct=iv+ct
		return (ct)

#Tag only for unification (Cha encryption)
	def Decrypt(self, text,tag=""):   # text= iv 16bytes + encrypted data
		try:
			iv=text[:16]  

			cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
			decryptor = cipher.decryptor()
			ct=decryptor.update(text[16:]) + decryptor.finalize()

			unpadder = padding.PKCS7(128).unpadder()
			data = unpadder.update(ct)
			data += unpadder.finalize()
		except:
			return b'ERR'
		else:
			return jsonpickle.loads(data.decode('utf-8'))

