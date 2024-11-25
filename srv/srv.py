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
    while req.find('quit')==-1:
    	try: 
        	print("GetMsg",address)
        	request = (await loop.sock_recv(client, 355))
        	print("Encrypted message:",request)
        	response = pickle.loads(mmenc.decrypt(request))
        	print(f'\nDecrypted message: {response}')
#        	print("GetIn4","\n")
        	req="quit"
#        	await loop.sock_sendall(client, response.encode('utf8'))
#        	print("GetIn5","\n")

    	except Exception as e:
        	print("handle client Error:", e,"\n")
    print("Exit from:",address,"\n")
    client.close()

async def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 15555))
    server.listen(8)
    server.setblocking(False)

    loop = asyncio.get_event_loop()

    while True:
        client, address = await loop.sock_accept(server)
        loop.create_task(handle_client(client,address))


asyncio.run(run_server())