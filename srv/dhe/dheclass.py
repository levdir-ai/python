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

	#p=21918172230924657872147853734504007131818840650450246907751010035580919959934823454972255939791854669150182607627091344659455301028730830280494523686764288718314209142722985088787804627654372178311194842066017565685512927423112348775162505877790078409039113646733095188584484340968724674750913237846104411885996222962651605228557785214285175180946971793648879631802174580874633953217169663135633194333704903265186997166060174905856179646034821720983277673324399357916844515353498677654018563495366827850312195829595129985823561148264104829585282168866782798164491158977853336033294323960694508750401073760758270317167
	g=2
	p=p_ffdhe2048

	def __init__(self):
		self.public_key=""
		self.private_key=""
		self.shared_key=""

	def GetPrivateKey(self):
		return self.private_key

	def GetPrivateKeyExp(self):
		pkexp=self.private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		)

		return pkexp


	def GetPublicKeyExp(self):
		pkexp=self.public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo,
		)

		return pkexp

#import pub key in GetPublicKeyExp() format
	def PublicKeyImp(self, pubkey):
#		pk=cryptography.hazmat.primitives.asymmetric.dh.DHPublicKey()
		pk = serialization.load_pem_public_key(pubkey, default_backend())

		return pk




	def GetPublicKey(self):
		return self.public_key

	def GenerateKeys(self):
		pn = dh.DHParameterNumbers(self.p,self.g)
		parameters = pn.parameters()
		self.private_key = parameters.generate_private_key()
		self.public_key = self.private_key.public_key()

	def Exchange(self, peer_public_key):
		self.shared_key=self.private_key.exchange(peer_public_key)
		return self.shared_key

#print(" shared_key:",base64.b64encode(shared_key).decode('utf-8'))

