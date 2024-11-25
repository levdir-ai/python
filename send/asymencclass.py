import base64 #export signature in readdable format (convert to base64)
import pickle #to serialize strings, objects, etc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class menc:
	def __init__(self, PubKeyFilename, PrivateKeyFilename):
	    self.public_key=""
	    self.private_key=""
	    ### load keys from PubKeyFilename, PrivateKeyFilename by class methods

#validate if  pub key defined
	def EncReady(self):
		return self.public_key!=""
#validate if  private key defined
	def DecReady(self):
		return self.private_key!=""

# Generate a new RSA key pair (public, private), and set to self.private_key, self.public_key
	def gen_keys(self):
	#code

#Return  private key
	def GetPrivateKey(self):
		return self.private_key

#Return  pub key
	def GetPublicKey(self):
		return self.public_key

# =============   Private key save to filename
	def save_pkey(self, filename):
	#code
	
# =============   Private key load. If error reurn -1 and set self.private_key to ""
	def load_pkey(self, filename):
	    try:
		#code
	    except:
		    self.private_key=""
		    return -1
	    else:
		    return self.private_key

# Save public key to Filename
	def save_pubkey(self, filename):
		#code		

# =============   Pub key load. If error reurn -1 and set self.public_key to ""
	def load_pubkey(self, filename):
	    try:
		#code
	    except:
		    self.public_key=""
		    return -1
	    else:
		    return self.public_key

# Encrypt the message using the public key (self.public_key). If not self.EncReady() return -1
# return encrypted text. MAX LENGTH 200 bytes (limitation of asymetric RSA)
#use pickle.dumps to serialize string, object etc
	def encrypt(self,message):
			#code
		return ciphertext

# Decrypting the message (=cyphertext) using your private key (self.private_key). If not self.DeccReady() return -1
# return decrypted text
	def decrypt(self,ciphertext):
		#code
		try:
		     #code
		except:
		    return -1
		else:
		    return pickle.loads(decrypted_message) # Read about pickle loads ans dumps!!!!. Use pickle.loads to deserialize 


# Sign the message using the private key (self.private_key.sign)
# retun signature in base64 encoding
	def sign(self,message):
		if (not self.DecReady()):
			return -1 #No private key loaded
		#code
		return base64.b64encode(signature).decode('utf-8') #convert signature to human readble format


#verify signature (self.public_key.verify). Decode signatture from sign method by base64.b64decode(signature),
#
	def verify(self,message,signature):
		if (not self.EncReady()):
			return -1 #No public key loaded
		try:
			#code
		except:
		    return False  #error on verification. Signature not valid
		else:
		    return True
