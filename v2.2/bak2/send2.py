import socket
import pickle
from cls.typeclass import pkt
from cls.dheclass import dhe 
from cls.scktclass import sckt
import base64
import sys


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server


print("Init Encryption")
d=dhe()
d.GenerateKeys()
print("Exp Pub Key\n")
pkk=d.GetPublicKey()
pk=d.GetPublicKeyExp()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    p= pkt("1","1","TTest",True, 1,b'11')
    s.sendall(sckt.build(p))

#    q=input("11")
    p= pkt("1","1","CHello",True, 1,pk)
    s.sendall(sckt.build(p))
    data,sz = sckt.parse(s.recv(10000))

#    print(f"Received {data.ptype!r}")
    if data.ptype=="SHello":
    	print("Got Hello from server")	
    	pkk=d.PublicKeyImp(data.message)
    	shared_key =d.Exchange(pkk)
    	print("Shared_key:",base64.b64encode(shared_key).decode('utf-8'))

#    q=input("22")
    p= pkt("1","1","Quit",True, 1,b'33')
#    s.sendall(sckt.build(p))
#    data = pickle.loads(s.recv(1024))
#    print(f"Received {data.ptype!r}")
    s.close()   	
