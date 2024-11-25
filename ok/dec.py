import base64
from encclass import menc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
 

if __name__ == '__main__':
    mmenc=menc("","privkey.pem")

    print("ENC ready:",mmenc.EncReady())
    print("DEC ready:",mmenc.DecReady())


    with open("encf", 'rb') as pem_in:
    	emessage = pem_in.read()

    decrypted_message=mmenc.decrypt(emessage)
    print(f'Decrypted message: {decrypted_message}')


