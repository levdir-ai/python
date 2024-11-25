import socket
import pickle
from typeclass import pkt
from dheclass import dhe 
import base64
import sys


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server


def buildpkt(obj):
	s=pickle.dumps(obj)	
	size=sys.getsizeof(s)+2
	print("PP size:",size+2)
	return size.to_bytes(2,'big')+s

print("Init Encryption")
p= pkt("1","1","TTest",True, 1,b' ')
ss=buildpkt(p)
print("\nPKT size :",int(ss[1])+int(ss[0]*256))