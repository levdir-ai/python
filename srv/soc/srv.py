import asyncio, socket
import base64
import pickle

from encclass import menc
from typeclass import pkt


async def handle_client(client,address):
    print("Get connection from:",address,"\n")
    mmenc=menc("pubkey.pem","privkey.pem")
    print("Init Encryption")
    print("ENC ready:",mmenc.EncReady())
    print("DEC ready:",mmenc.DecReady(),"\n")

    loop = asyncio.get_event_loop()
    req = ""
    fout=open("srv.out", 'a')

    while req.find('quit')==-1:
    	try: 
	       	print("GetMsg",address)
	       	request = (await loop.sock_recv(client, 64000))
	       	print("Encrypted message:",request)
	       	response = pickle.loads(request)
	       	print("Msg Type:",type(response))
	       	print(f'\nDecrypted message: {response}')
#	       	fout.write(response.decode('utf-8'))
#       	print("GetIn4","\n")
#	       	req="quit"
	       	req=response
        	await loop.sock_sendall(client, b'ok')
        	print("GetIn5","\n")

    	except Exception as e:
        	print("handle client Error:", e,"\n")
        	await loop.sock_sendall(client, b'Error')
	       	req="quit"
    print("Exit from:",address,"\n")
    fout.close()
    client.close()

async def run_server():
    print("Run server")	
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 15555))
    server.listen(8)
    server.setblocking(False)

    loop = asyncio.get_event_loop()
    while True:
        client, address = await loop.sock_accept(server)
        loop.create_task(handle_client(client,address))

print("AsyncRun -1")	
try:
	asyncio.run(run_server())
except  KeyboardInterrupt:
	print("CTRL-C pressed Async")
print("AsyncRun 1")	