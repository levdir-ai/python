import base64
#import json
import pickle

from encclass import menc
from typeclass import pkt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import array 

if __name__ == '__main__':
    message = input("Message to encrypt:").encode()
    mmenc=menc("pubkey.pem","privkey.pem")

#    mmenc=menc("pubkey.pem","")
#    mmenc.gen_keys()

    print("ENC ready:",mmenc.EncReady())
    print("DEC ready:",mmenc.DecReady())

#    pk = mmenc.gen_key()
  #  filename = 'privkey.pem'
    #mmenc.save_key(pk, filename)

#    mmenc.load_pkey(filename)
 #   filename = 'pubkey.pem'
#    mmenc.load_pubkey(filename)

#print (mmenc.hello())

print(f'Original message: {message}')
sgn=mmenc.sign(message)
p= pkt("1.1","1.0","hello", 123,"Hello World!")

#serialized_data = pickle.dumps(p)
#print("Serialized:\n",serialized_data,"\n")

#p = pickle.loads(serialized_data)
#print("DeSerialized:\n",p,"\n")
#
#print("DeSerialized:From:\n",p.source,"\n")


#print("jsin:", pickle.dumps(p))
print ("Signature:",sgn)
#with open("sgn", 'w') as pem_out:
#	        pem_out.write(sgn)



emessage=mmenc.encrypt(message)
with open("encf", 'wb') as pem_out:
	        pem_out.write(emessage)

print ("enc msg:",emessage.decode('utf8'))
#print(f'Encrypted message: {emessage}')
decrypted_message=mmenc.decrypt(emessage)
print(f'Decrypted message: {decrypted_message}')


print("Sign verification:", mmenc.verify(decrypted_message,sgn))

