import socket
import pickle
from typeclass import pkt
from dheclass import dhe 
import base64


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server

print("Init Encryption")
d=dhe()
d.GenerateKeys()
print("Exp Pub Key\n")
pk=d.GetPublicKeyExp()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    p= pkt("1","1","CHello",True, 1,pk)
#1
    s.sendall(pickle.dumps(p))
#2 
    data = pickle.loads(s.recv(60000))
    print(f"Received {data.ptype!r}")
#    print("Data:",data)	

    if data.ptype=="SHello":
    	print("Got Hello from server")	
    	pkk=d.PublicKeyImp(data.message)
    	shared_key =d.Exchange(pkk)
    	print("Shared_key:",base64.b64encode(shared_key).decode('utf-8'))
#    	data = pickle.loads(s.recv(60000))
#   	print(f"Received {data.ptype!r}")

    p= pkt("1","1","Quit",True, 1,b' ')
    #s.sendall(pickle.dumps(p))
    #data = pickle.loads(s.recv(1024))
    #print(f"Received {data.ptype!r}")
    s.close()   	
