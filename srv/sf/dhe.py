from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes

import base64
import os

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


#print(p_ffdhe2048)


# Generate some parameters. These can be reused.
print("0")
#parameters = dh.generate_parameters(generator=2, key_size=2048)
#print("\n parameters P:", parameters.parameter_numbers().p)
#print("\n parameters G:", parameters.parameter_numbers().g)
#print("\n parameters Q:", parameters.parameter_numbers().q)
#print("01")
pn = dh.DHParameterNumbers(p,g)
pn1 = dh.DHParameterNumbers(p,g)
print("01")
parameters = pn.parameters()
parameters1 = pn.parameters()
#peer_public_numbers = dh.DHPublicNumbers(1, pn)
#print("peer_public_numbers:", peer_public_numbers)

#print("peer_public_numbers:",peer_public_numbers )
#peer_public_key = peer_public_numbers.public_key()
print("1")
# Generate a private key for use in the exchange.
private_key = parameters.generate_private_key()
pk=private_key.private_bytes(
	        encoding=serialization.Encoding.PEM,
	        format=serialization.PrivateFormat.PKCS8,
	        encryption_algorithm=serialization.NoEncryption()
	    )
#print("private_key:",pk)
private_key1 = parameters1.generate_private_key()
pk1=private_key1.private_bytes(
	        encoding=serialization.Encoding.PEM,
	        format=serialization.PrivateFormat.PKCS8,
	        encryption_algorithm=serialization.NoEncryption()
	    )

#print("private_key:",pk1)
print("2")
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.
peer_public_key = private_key.public_key()
peer_public_key1 = private_key1.public_key()

shared_key = private_key.exchange(peer_public_key1)
print(" shared_key:",base64.b64encode(shared_key).decode('utf-8'))
shared_key1 = private_key1.exchange(peer_public_key)
print("\nshared_key1:",base64.b64encode(shared_key1).decode('utf-8'))
print("Equality:", shared_key==shared_key1)

print("3")

exit()


# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)
print("derived_key", derived_key.hex())

# For the next handshake we MUST generate another private key, but
# we can reuse the parameters.
private_key_2 = parameters.generate_private_key()
peer_public_key_2 = parameters.generate_private_key().public_key()
shared_key_2 = private_key_2.exchange(peer_public_key_2)
derived_key_2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key_2)



