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
pemlines='Hello world!'
#p= pkt("1.1","1.0","hello", True, 123,"Hello World!")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(pickle.dumps(pemlines))
    data = s.recv(1024)
    print(f"Received {data!r}")

    pemlines='Hello wrld!'
    s.sendall(pickle.dumps(pemlines))
    data = s.recv(1024)
    print(f"Received {data!r}")

    pemlines='quit'
    s.sendall(pickle.dumps(pemlines))
    data = s.recv(1024)
    print(f"Received {data!r}")