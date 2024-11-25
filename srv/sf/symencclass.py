import os
import array
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class symenc:
	def __init__(self):
		self.salt=b'Some pepper!!!!'
		self.key=""

#pastxt string

	def pass2key(self, pastxt):
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=self.salt,
			iterations=480000,
		)
		self.key = kdf.derive(bytes(pastxt,'utf-8'))

	def GetKey(self):
		return self.key

	def encrypt(self, data):
		padder = padding.PKCS7(128).padder()
		padded_data = padder.update(pickle.dumps(data))
		padded_data += padder.finalize()

		iv = os.urandom(16)
		cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
		encryptor = cipher.encryptor()
		ct = encryptor.update(padded_data) + encryptor.finalize()
		ct=iv+ct
		print("IV:",iv.hex())
		return (ct)

	def decrypt(self, text):
		iv=text[:16]  
		print("IV:",iv.hex())

		cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
		decryptor = cipher.decryptor()
		ct=decryptor.update(text[16:]) + decryptor.finalize()

		unpadder = padding.PKCS7(128).unpadder()
		data = unpadder.update(ct)
		data += unpadder.finalize()

		return pickle.loads(data)

	def test(self):
		key = os.urandom(32)
		with open("qq", 'rb') as pem_in:
			pemlines = pem_in.read()
		pem_in.close()
		print(pemlines)
		(iv,etxt)=self.encrypt(key,pemlines)
		print(etxt)
		txt=self.decrypt(key,iv,etxt)
		print("\n\n\n",txt)
		with open("enctout1", 'wb') as pem_out:
			pem_out.write(txt)
		pem_out.close()

