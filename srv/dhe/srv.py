import asyncio, socket
import base64
import pickle

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
	       	#print("Encrypted message:",request)
	       	response = pickle.loads(request)
	       	#print("Msg Type:",type(response))
#	       	print(f'Decrypted message: {response}\n')
	       	if isinstance(response, pkt):
	       		print("Got PKT. Type:",response.ptype)
	       		match response.ptype:
	       			case "CHello":
	       				pkk=d.PublicKeyImp(response.message)
	       				shared_key =d.Exchange(pkk)
	       				print("Shared_key:",base64.b64encode(shared_key).decode('utf-8'))


			        	pk=d.GetPublicKeyExp()
			        	p= pkt("1","1","SHello",False, 1,pk)
	       				await loop.sock_sendall(client, pickle.dumps(p))

	       		match response.ptype:
	       			case "Quit":
				       	req=False
				       	LoopQuit=True
#        	p= pkt("1","1","OK",False, 1,b' ')
 #       	await loop.sock_sendall(client, pickle.dumps(p))
		
        	print("GetIn5","\n")

    	except Exception as e:
        	print("handle client Error:", e,"\n")
        	await loop.sock_sendall(client, b'Error')
	       	req="quit"
    print("========================== Close connection from:",address," ===========================\n")
    client.close()

async def run_server():
    global LoopQuit

    print("Run server")	
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 15555))
    server.listen(8)
    server.setblocking(False)

    loop = asyncio.get_event_loop()
    while not LoopQuit:
        print("LoopQuit:",LoopQuit)
        client, address = await loop.sock_accept(server)
        print("Loop1:",LoopQuit)
        loop.create_task(handle_client(client,address))
        print("Loop2:", LoopQuit)

print("AsyncRun -1")	
try:
	LoopQuit = False
	asyncio.run(run_server())
except  KeyboardInterrupt:
	print("CTRL-C pressed Async")
	server.close()
print("AsyncRun 1")	