import logging
logger = logging.getLogger("main")

from cls.dbl import UserManager

from cls.processcmdcl import processCmd

from cls.blacklist import IPBlacklist
global Blacklist

import hashlib, uuid
import asyncio, socket
import base64
import pickle
import sys
import os

from cls.typeclass import pkt,Hello,Host,ConnectionParam
from cls.scktclass import sckt

from cls.dheclass import dhe 
from cls.asymencclass import asymenc
from cls.symencclass import symenc

global LoopQuit
cnn = ConnectionParam(
    dbname="postgres",
    user="asgu",
    password="asgu",
    host="localhost"
)


async def handle_client(client,address):
    global LoopQuit
    UMgr=""
    usr=""
    if LoopQuit:
    	return

    logger.info("========== Got connection from:" +str(address)+" ==========")
    logger.info("Init Encryption")
# Init DHE
    d=dhe()
# Init ASYM
    mmenc=asymenc("cfg/pubkey.pem","cfg/privkey.pem")
#Init SYM
    senc=symenc()

    loop = asyncio.get_event_loop()
    response=""
    request=b''
    size=0	

    while (request:=request + (await loop.sock_recv(client, 8192))) and len(request)>0 and not Blacklist.IsBlacklisted(address[0]):
    	try: 

	       	logger.debug("Got Message from: %s. Size:%d",str(address), len(request))
	       	#print("Message", len(request)," Body:\n",request.decode('latin-1'))
	       	while len(request)>=sckt.size(request) and sckt.size(request)!=0:
	       		(response,size)=sckt.parse(request,senc)
#       			print("\n\nSRV2 Size:",size,"  len(request):",len(request))
	       		request=request[size:]
#	       		print("Response:",response)
	       		if response.message==b'ERR':
		       		logger.error("		Error Decrypting message!")
		       		Blacklist.DecreaseReputation(address[0])
		       		continue

		       	if isinstance(response, pkt):
		       		logger.info("Got PKT from:	%s.",str(address))
		       		logger.info("		PKT:Type:%s, Encryption:%s, Size:%d bytes",response.ptype,response.enc,size)

		       		match response.ptype:
		       			case "Quit":
					       	LoopQuit=True
					       	logger.debug("Quit: done")

		       			case "CHello":
		       				logger.info("		CHello from:%s",str(address))
		       				s=response.message
		       				d.GenerateKeys()
		       				s.Encryption=mmenc.decrypt(s.Encryption)
		       				logger.debug("		DEcrypt:%s",s.Encryption)
		       				if s.Encryption==-1: 
		       					logger.warning("		Client validation by Public Key failed! Invalid Public Key! Exit.")
		       					Blacklist.DecreaseReputation(address[0])
		       					p= pkt("1","1","Error","", 1,b'Invalid Public Key')
		       					await loop.sock_sendall(client, sckt.build(p))
		       					continue
		       				else: 
		       					logger.info("		Client validation by Public Key successful!") 				
		       		
		       				senc.pass2key(s.Encryption)
		       				s.Encrypted=senc.decrypt(s.Encrypted)
		       				logger.info("		Got Client DHE certificate.")
#		       				print("User Password hash:",s.Encrypted.UserHash)
		       				UMgr=UserManager(cnn)
		       				usr=UMgr.Validate(s.Encrypted.User,s.Encrypted.PHash)
		       				if usr is None:
		       					logger.error("		Password incorrect for user:" + str(s.Encrypted.User))
		       					Blacklist.DecreaseReputation(address[0])
		       					p= pkt("1","1","Error","", 1,b'Invalid User name / password')
		       					UMgr.Close()
		       					await loop.sock_sendall(client, sckt.build(p))
		       					continue

		       				k=d.Exchange(d.PublicKeyImp(s.Encrypted.DHCert))
		       				logger.info("		Shared_Key:%s....%s",k.hex()[:10],k.hex()[-10:])
		       				senc.pass2key(k.hex())

		       				logger.info("		SHello to:%s",str(address))

		       				ss=Hello(Encrypted=Host( 
							Random = os.urandom(16),
							User = s.Encrypted.User,
							PHash = b'',
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

				        	p= pkt("1","1","SHello","", 1,ss)
		       				await loop.sock_sendall(client, sckt.build(p))

		       				senc.pass2key(ss.Encrypted.Random.hex()+k.hex()+s.Encrypted.Random.hex())
		       				logger.info("		DHSYM Encryption enabled.")
		       				logger.debug("		EXIT CHello")

		       			case "Data":
		       				logger.debug("		Data")
		       				logger.info("		Data Message:%s",response.message.decode('latin-1')[:50])


		       			case "CMD":
		       				logger.debug("		CMD")
		       				logger.info("		CMD Message:%s",response.message.cmd)
		       				#u=UserManager(cnn)
		       				if response.message.cmd=="GetList": 
		       					ul = UMgr.GetList()
		       					#print("UList:",ul)
				        		p= pkt("1","1","GetListData","", 1,ul)
		       					await loop.sock_sendall(client, sckt.build(p))

		       				UMgr.Close()
		       				#await process_cmd(response.message)

		       			case "Test":
					       	print("Test: done")

		       			case _:
	       					Blacklist.DecreaseReputation(address[0])
					       	logger.warning("Unknown type:%s done.",response.ptype)

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
    global Blacklist

    logger.info('Run server')
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 15555))
    server.listen(8)
    server.setblocking(False)

    Blacklist=IPBlacklist()
#    Blacklist.DecreaseReputation("127.0.0.1")

    loop = asyncio.get_event_loop()
    while not LoopQuit:
#        print("----LoopQuit:",LoopQuit)
        client, address = await loop.sock_accept(server)
#        print("----Loop1:",address[0])
        if not Blacklist.IsBlacklisted(address[0]) :
	        loop.create_task(handle_client(client,address))
        else:
        	logger.warning("Blacklisted IP:	%s connects. Rejected!",address[0])
#        print("----Loop2:", LoopQuit)


if __name__ == '__main__':

    logging.basicConfig(filename='log/asgusrv.log', level=logging.INFO, format='%(asctime)s: %(levelname)s:%(module)s.%(funcName)s: %(message)s')
#INFO
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    console_handler.setLevel(logging.INFO)
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
