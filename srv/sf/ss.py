import socket, sys
import pickle
from encclass import menc
from typeclass import pkt
from symencclass import symenc

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#mmenc=menc("pubkey.pem","privkey.pem")
#print("Init Encryption\n")
#print("ENC ready:",mmenc.EncReady())
#print("DEC ready:",mmenc.DecReady())

#message = input("Message to encrypt:")
#salt = os.urandom(16)
#salt=b'Some pepper!!!!'
#print("Salt:",salt.hex())

with open("qq", 'rb') as pem_in:
	pemlines = pem_in.read()
pem_in.close()
txt="Hello world!"

ss=symenc()
print(ss.pass2key("My password"))
etxt= ss.encrypt(pemlines)
print ("etxt:",etxt.hex())
txt1=ss.decrypt(etxt)
print("Decrypted:",txt1)
