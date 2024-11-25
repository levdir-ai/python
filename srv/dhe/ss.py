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
	return size.to_bytes(2,'big')+s

print("Init Encryption")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    p= pkt("1","1","TTest",True, 1,b' ')
    s.sendall(buildpkt(p))
    sys.exit()

    q=input("11")
    print("Init Encryption")
    s.sendall(buildpkt(p))
    q=input("22")
    p= pkt("1","1","Quit",True, 1,b' ')
    s.sendall(buildpkt(p))
#    data = pickle.loads(s.recv(1024))
#    print(f"Received {data.ptype!r}")
    s.close()   	
