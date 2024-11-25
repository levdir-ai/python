import logging
logger = logging.getLogger("main")

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class dhe:
	# ffdhe2048 value from RFC 7919
	p_ffdhe2048 = int(
	    "0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1"
	    "D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9"
	    "7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561"
	    "2433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
	    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735"
	    "30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB"
	    "B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19"
	    "0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
	    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73"
	    "3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA"
	    "886B423861285C97FFFFFFFFFFFFFFFF",
	    16
	)
	g=2
	p=p_ffdhe2048

	def __init__(self):
		logger.info("		Init DHE")
		self.public_key=""
		self.private_key=""
		self.shared_key=""


	def GetPrivateKey(self):
		logger.warning("		DHE Private key access")
		return self.private_key

	def GetPrivateKeyExp(self):
		logger.warning("		DHE Private key export")
		pkexp=self.private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)

		return pkexp


	def GetPublicKeyExp(self):
		logger.warning("		DHE Public key export.")
		pkexp=self.public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo,
		)

		return pkexp

#import pub key in GetPublicKeyExp() format
	def PublicKeyImp(self, pubkey):
		logger.warning("		DHE Public key import: %s....%s",pubkey[27:37].decode('latin-1'),pubkey[-37:-26].decode('latin-1'))
		pk = serialization.load_pem_public_key(pubkey, default_backend())

		return pk

	def GetPublicKey(self):
		return self.public_key

	def GenerateKeys(self):
		logger.warning("		DHE Generate New Keys.")
		pn = dh.DHParameterNumbers(self.p,self.g)
		parameters = pn.parameters()
		self.private_key = parameters.generate_private_key()
		self.public_key = self.private_key.public_key()

	def Exchange(self, peer_public_key):
		logger.warning("		DHE Exchange keys")
		self.shared_key=self.private_key.exchange(peer_public_key)
		return self.shared_key


