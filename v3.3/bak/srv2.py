import logging
logger = logging.getLogger(__name__)

import asyncio, socket
import base64
import pickle
import sys
import os

from cls.typeclass import pkt,Hello,Host
from cls.scktclass import sckt

from cls.dheclass import dhe 
from cls.asymencclass import asymenc
from cls.symencclass import symenc

global LoopQuit

async def handle_client(client,address):
    global LoopQuit
    if LoopQuit:
    	return

    logger.info("========== Got connection from:" +str(address)+" ==========")
    logger.info("Init Encryption")
# Init DHE
    d=dhe()
    d.GenerateKeys()
# Init ASYM
    mmenc=asymenc("cfg/pubkey.pem","cfg/privkey.pem")
#Init SYM
    senc=symenc()

    loop = asyncio.get_event_loop()
    response=""
    request=b''
    size=0	

    while (request:=request + (await loop.sock_recv(client, 8192))) and len(request)>0:
    	try: 

	       	logger.debug("Got Message. Size:%d", len(request))
	       	#print("Message", len(request)," Body:\n",request.decode('latin-1'))
	       	while len(request)>=sckt.size(request) and sckt.size(request)!=0:
	       		(response,size)=sckt.parse(request,senc)
#       			print("\n\nSRV2 Size:",size,"  len(request):",len(request))
	       		request=request[size:]
#	       		print("Response:",response)
	       		if response.message==b'ERR':
		       		logger.error("Error Decrypting message!")
		       		continue

		       	if isinstance(response, pkt):
		       		logger.info("Got PKT.	Type:%s Encryption:%s",response.ptype,response.enc)
		       		match response.ptype:
		       			case "Quit":
					       	LoopQuit=True
					       	logger.debug("Quit: done")

		       			case "CHello1":
		       				logger.info("		CHello from:%s",str(address))
		       				s=response.message
		       				s.Encryption=mmenc.decrypt(s.Encryption)
		       				logger.debug("		DEcrypt:%s",s.Encryption)
		       				if s.Encryption==-1: 
		       					logger.error("		Invalid Public Key! Exit.")
		       					p= pkt("1","1","Error","", 1,b'Invalid Public Key')
		       					await loop.sock_sendall(client, sckt.build(p))
		       					continue
		       				else: logger.debug("		Valid Public Key!") 				
		       				senc.pass2key(s.Encryption)
		       				s.Encrypted=senc.decrypt(s.Encrypted)
		       				#print("\nClient CERT:",s.Encrypted.DHCert)

		       				k=d.Exchange(d.PublicKeyImp(s.Encrypted.DHCert))
		       				logger.info("		Shared_Key:\n%s",k.hex())
		       				senc.pass2key(k.hex())

		       				logger.info("		SHello to:%s",str(address))

		       				ss=Hello(Encrypted=Host( 
							Random = os.urandom(16),
							UserHash = b'',
							AppName ="ASGU",
							AppVersion ="1.0",
							CertVersion = "DHE",
							DHCert = d.GetPublicKeyExp(),
							IP=sckt.ip4_addresses(),
							Host=socket.gethostname(),
							),
							Encryption= b'None',
							Signature=b''
						)
		       				ss.Signature=mmenc.sign(ss.Encrypted)

				        	p= pkt("1","1","SHello1","", 1,ss)
		       				await loop.sock_sendall(client, sckt.build(p))

		       				senc.pass2key(ss.Encrypted.Random.hex()+k.hex()+s.Encrypted.Random.hex())

		       				logger.debug("		EXIT CHello1")

		       			case "Data":
		       				logger.info("		Data")
		       				logger.debug("		Message:%s",response.message.decode('latin-1')[:50])

		       			case "Test":
					       	print("Test: done")

		       			case _:
					       	logger.warnnig("Unknown type:%s done.",response.ptype)
		
        	size=0
        	logger.debug("Exit Message")
    	except Exception as e:
        	logger.error("handle client Error:%s", e,"\n")
	       	await loop.sock_sendall(client, b'Error')
	       	#req="quit"
    logger.info("========== Close connection from:"+str(address)+" ==========")
    #client.close()

async def run_server():
    global LoopQuit

    logger.info('Run server')
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 15555))
    server.listen(8)
    server.setblocking(False)

    loop = asyncio.get_event_loop()
    while not LoopQuit:
#        print("----LoopQuit:",LoopQuit)
        client, address = await loop.sock_accept(server)
#        print("----Loop1:",LoopQuit)
        loop.create_task(handle_client(client,address))
#        print("----Loop2:", LoopQuit)


if __name__ == '__main__':
    logging.basicConfig(filename='myapp.log', level=logging.INFO, format='%(asctime)s: %(levelname)s:%(module)s.%(funcName)s: %(message)s')
    console_handler = logging.StreamHandler()
    logger.addHandler(console_handler)
    logger.info('>>>>>>>>>>>>>>>>>>>>>> Started <<<<<<<<<<<<<<<<<<<<<<<<<')
    os.system('clear')
    print("Server initializaion.")	
    try:
    	LoopQuit = False
    	asyncio.run(run_server())
    except  KeyboardInterrupt:
    	print("CTRL-C pressed Async")
    logger.info('Finished\n\n')
