from typeclass import pkt
from encclass import menc

import pickle

ba=bytearray([65,54,45,67,89,98])
p= pkt("1.1","1.0","hello", True,123,"Hello World!")
#bytes()

mmenc=menc("pubkey.pem","privkey.pem")
print("ENC ready:",mmenc.EncReady())
print("DEC ready:",mmenc.DecReady(),"\n")
print (mmenc.encrypt(pkt))

#print(type(ba),":",ba)
#print(ba.decode())

#serialized_data = pickle.dumps(ba)
#print(type(serialized_data),":",serialized_data);

#p= pkt("1.1","1.0","hello", True,123,"Hello World!")


#print("Serialized:\n",serialized_data,"\n")

#p = pickle.loads(serialized_data)
#print("DeSerialized:\n",p,"\n")
#
#print("DeSerialized:From:\n",p.source,"\n")


#print("jsin:", pickle.dumps(p))
