# RSA is a public-key algorithm for encrypting and signing messages.
import logging
logger = logging.getLogger("main")

import base64
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class asymenc:
# Path to the PublicKey and PrivateKey files in .pem format
	def __init__(self, PubKeyFilename, PrivateKeyFilename):
	    logger.info("		Init ASYM")

	    self.public_key=""
	    self.private_key=""
#	    print("PubKey:",PubKeyFilename)
	    if (PubKeyFilename!=""):
	    	self.LoadPubKey(PubKeyFilename)
	    	logger.info("Public Key Loaded")
	    if (PrivateKeyFilename!=""):
	    	self.LoadPrivKey(PrivateKeyFilename)
	    	logger.info ("Private Key Loaded")

	def EncReady(self):
		return self.public_key!=""
	def DecReady(self):
		return self.private_key!=""

# Generate a new RSA key pair (public, private)
	def GenKeys(self):
	    self.private_key = rsa.generate_private_key(
	        public_exponent=65537, key_size=2048, backend=default_backend()
	    )
	    self.public_key = self.private_key.public_key()


	def GetPrivateKey(self):
		return self.private_key


	def GetPublicKey(self):
		return self.public_key

# =============   Private key save
	def SavePrivKey(self, filename):
	    pem = pk.private_bytes(
	        encoding=serialization.Encoding.PEM,
	        format=serialization.PrivateFormat.TraditionalOpenSSL,
	        encryption_algorithm=serialization.NoEncryption()
	    )
	    with open(filename, 'wb') as pem_out:
	        pem_out.write(pem)

# =============   Private key load
	def LoadPrivKey(self, filename):
	    try:
		    with open(filename, 'rb') as pem_in:
		        pemlines = pem_in.read()
		    self.private_key = serialization.load_pem_private_key(pemlines, None, default_backend())
	    except:
		    self.private_key=""
		    return -1
	    else:
		    return self.private_key

# Public keys
	def SavePubKey(self, filename):
	    pem_public_key = self.public_key.public_bytes(
   	  	encoding=serialization.Encoding.PEM,
  	  	format=serialization.PublicFormat.SubjectPublicKeyInfo
	    )
	    with open(filename, 'wb') as pem_out:
	        pem_out.write(pem_public_key)


	def LoadPubKey(self, filename):
	    try:
		    with open(filename, 'rb') as pem_in:
		        pemlines = pem_in.read()
		        self.public_key = serialization.load_pem_public_key(pemlines, default_backend())
	    except:
		    self.public_key=""
		    return -1
	    else:
		    return self.public_key

# Encrypt the message using the public key
	def Encrypt(self,message):
		if (not self.EncReady()) or (len(pickle.dumps(message))>190):
			return -1 #No Pub key loaded
		
		ciphertext = self.public_key.encrypt(
		    pickle.dumps(message),
		    padding.OAEP(
		        mgf=padding.MGF1(algorithm=hashes.SHA256()),
		        algorithm=hashes.SHA256(),
		        label=None
		    )
		)         
		return ciphertext

# Decrypting the message (=cyphertext) using your private key
	def Decrypt(self,ciphertext):
		if (not self.DecReady()):
			return -1 #No Private key loaded
		try:
			decrypted_message = self.private_key.decrypt(
			    ciphertext,
			    padding.OAEP(
			        mgf=padding.MGF1(algorithm=hashes.SHA256()),
			        algorithm=hashes.SHA256(),
			        label=None
			    )
			)
		except:
		    return -1
		else:
		    return pickle.loads(decrypted_message)


# Sign the message using the private key
# retun signature in base64 encoding
	def Sign(self,message):
		if (not self.DecReady()):
			return -1 #No private key loaded
		signature = self.private_key.sign(
		    pickle.dumps(message),
		    padding.PSS(
		        mgf=padding.MGF1(algorithm=hashes.SHA256()),
		        salt_length=padding.PSS.MAX_LENGTH
		    ),
		    hashes.SHA256()
		)         
		return base64.b64encode(signature).decode('utf-8')


	def Verify(self,message,signature):
		if (not self.EncReady()):
			return -1 #No public key loaded
		try:
			verfication = self.public_key.verify(
			    base64.b64decode(signature),
			    pickle.dumps(message),
			    padding.PSS(
			        mgf=padding.MGF1(algorithm=hashes.SHA256()),
			        salt_length=padding.PSS.MAX_LENGTH
			    ),
			    hashes.SHA256()
			)         
		except:
		    return False
		else:
		    return True
