import asyncio, socket
import base64

from encclass import menc
from typeclass import pkt


async def handle_client(client,address):
    print("GetIn from:",address,"\n")
    mmenc=menc("pubkey.pem","privkey.pem")
    print("Init Encryption\n")
    print("ENC ready:",mmenc.EncReady())
    print("DEC ready:",mmenc.DecReady())

    loop = asyncio.get_event_loop()
    req = ""
    while req.find('quit')==-1:
    	try: 
        	print("GetMsg",address,"\n")
        	request = (await loop.sock_recv(client, 255))
        	req = request.decode('utf8')

        	print("Req:",req.find('quit'), "\n")
#        	response = str(eval(request)) + '\n'
        	response = mmenc.encrypt(request) # + '\n'
        	rsp =base64.b64encode(response).decode('utf-8')+ '\n'

        	print("GetIn4","\n")
        	await loop.sock_sendall(client, rsp.encode('utf8'))
        	print("GetIn5","\n")

    	except Exception as e:
        	print("handle client Error:", e.message, e.args,"\n")
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