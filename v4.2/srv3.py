import logging
logger = logging.getLogger("main")

from cls.dbl import UserManager
#from cls.processcmdcl import processCmd
from cls.cmdclass import ProcessCmd 


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
from cls.helloclass import DHEHello

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
    Usr=""
    if LoopQuit:
    	return

    logger.info("========== Got connection from:" +str(address)+" ==========")
    logger.info("Init Encryption")
#Init SYM
    SymEnc=symenc()

    loop = asyncio.get_event_loop()
    response=""
    request=b''
    size=0	

    while (request:=request + (await loop.sock_recv(client, 8192))) and len(request)>0 and not Blacklist.IsBlacklisted(address[0]):
    	try: 

	       	logger.debug("Got Message from: %s. Size:%d",str(address), len(request))
	       	#print("Message", len(request)," Body:\n",request.decode('latin-1'))
	       	while len(request)>=sckt.Size(request) and sckt.Size(request)!=0:
	       		(response,size)=sckt.Parse(request,SymEnc)
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
		       				UMgr=UserManager(cnn)
		       				
		       				err,ss,Usr =DHEHello.Server(UMgr,SymEnc,"cfg/privkey.pem",response.message)
		       				if int(err)<0 : 
		       					print("Hello error",ss)
		       					UMgr.Close()
		       					Blacklist.DecreaseReputation(address[0])
		       					if err==-1: errm=b'Invalid Public Key'
		       					if err==-2: errm=b'Invalid User name / password'
		       					p= pkt("1","1","Error","", 1,errm)
		       					await loop.sock_sendall(client, sckt.Build(p))
		       					continue

		       				logger.info("		SHello to:%s",str(address))
				        	p= pkt("1","1","SHello","", 1,ss)
		       				await loop.sock_sendall(client, sckt.Build(p))
		       				
		       				logger.info("		DHSYM Encryption enabled.")
		       				logger.debug("		EXIT CHello")

		       			case "Data":
		       				logger.debug("		Data")
		       				logger.info("		Data Message:%s",response.message.decode('latin-1')[:50])


		       			case "CMD":
		       				logger.debug("		CMD")
		       				logger.info("		CMD Message:%s",response.message.cmd)
#		       				print("User ID and CMD",Usr.user_id,response.message.cmd)

		       				if UMgr.IsCommandAllowed(Usr.user_id,response.message.cmd): 
#		       				if response.message.cmd!="": 
				        		ClassList={"UserManager":UMgr}
				        		ul = ProcessCmd.CallMethod(ClassList,response.message.cmd,response.message.args)
		       					#print("UList:",ul)
				        		p= pkt("1","1",response.message.cmd+':Response:',"", 1,ul)
		       					await loop.sock_sendall(client, sckt.Build(p))
		       				else:
		       					logger.info("		Command not allowed:%s User:%s",response.message.cmd,Usr.username)
				        		p= pkt("1","1","ERROR","", 1,b"Command not allowed!")
		       					await loop.sock_sendall(client, sckt.Build(p))

		       				#await process_cmd(response.message)

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
    UMgr.Close()
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
    print("Server initializaion (v.3.0).")	
    try:
    	LoopQuit = False
    	asyncio.run(run_server())
    except  KeyboardInterrupt:
    	print("CTRL-C pressed Async")
    logger.info('Finished\n\n')
