import base64
from encclass import menc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import array 

if __name__ == '__main__':
    message = input("Message to encrypt:").encode()
    mmenc=menc("pubkey.pem","")   #1
    print("ENC ready:",mmenc.EncReady())
    print("DEC ready:",mmenc.DecReady())
    emessage=mmenc.encrypt(message)  #2

    with open("encf", 'wb') as pem_out:
    	pem_out.write(emessage)


