import asyncio, socket
import base64
import pickle
import sys

from typeclass import pkt
from dheclass import dhe 

global LoopQuit

async def handle_client(client,address):
    global LoopQuit
    if LoopQuit:
    	return

    print("======================= Get connection from:",address," =========================")
    print("Init Encryption")
    d=dhe()
    d.GenerateKeys()

    loop = asyncio.get_event_loop()
    req = True
    p= pkt("1","1","OK",False, 1,b'')
    while req:
    	try: 
	       	print("\nGot Message",address)
	       	request = (await loop.sock_recv(client, 4096))
	       	print("\nRequest size:",sys.getsizeof(request))
	       	print("\nRequest:",request)
	       	response = pickle.loads(request[2:])
	       	print("\nPKT size :",int(request[1])+int(request[0]*256))
	       	if isinstance(response, pkt):
	       		print("Got PKT. Type:",response.ptype)
	       		match response.ptype:
	       			case "Quit":
				       	req=False
				       	LoopQuit=True
#				       	p= pkt("1","1","OK",False, 1,b' ')
#				       	await loop.sock_sendall(client, pickle.dumps(p))
				       	print("Quit: done")
	       			case "Test":
#				       	p= pkt("1","1","OK",False, 1,b' ')
#				       	await loop.sock_sendall(client, pickle.dumps(p))
				       	print("Test: done")
		
        	print("GetIn5","\n")
    	except Exception as e:
        	print("handle client Error:", e,"\n")
        	await loop.sock_sendall(client, b'Error')
	       	req="quit"
    print("========================== Close connection from:",address," ===========================\n")
    #client.close()

async def run_server():
    global LoopQuit

    print("Run server")	
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 15555))
    server.listen(8)
    server.setblocking(False)

    loop = asyncio.get_event_loop()
    while not LoopQuit:
        print("----LoopQuit:",LoopQuit)
        client, address = await loop.sock_accept(server)
        print("----Loop1:",LoopQuit)
        loop.create_task(handle_client(client,address))
        print("----Loop2:", LoopQuit)

print("AsyncRun -1")	
try:
	LoopQuit = False
	asyncio.run(run_server())
except  KeyboardInterrupt:
	print("CTRL-C pressed Async")
print("AsyncRun 1")	