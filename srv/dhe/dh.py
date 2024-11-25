from dheclass import dhe 
import pickle

d=dhe()
d1=dhe()
d.GenerateKeys()
d1.GenerateKeys()
skey=d.Exchange(d1.GetPublicKey())
print(skey.hex())
pk=d.GetPublicKeyExp()
pkk=d.PublicKeyImp(pk)

skey1=d1.Exchange(pkk)
print("\n",skey1.hex())

#pk=d.GetPublicKeyExp()
#print(pk)
#pkk=d.PublicKeyImp(pk)