import socket
import pickle
from encclass import menc
from typeclass import pkt


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server


mmenc=menc("pubkey.pem","privkey.pem")
print("Init Encryption\n")
print("ENC ready:",mmenc.EncReady())
print("DEC ready:",mmenc.DecReady())

#message = input("Message to encrypt:")
with open("privkey.pem", 'rb') as pem_in:
	pemlines = pem_in.read()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(mmenc.encrypt(pickle.dumps(pemlines)))
#    data = s.recv(1024)

#print(f"Received {data!r}")