from datetime import datetime
import logging
import hashlib, uuid
import asyncio, socket
import base64
import pickle
import sys
import os
import configparser
from time import sleep

from cls.blusermanager3 import UserManager
from cls.bltest import Test
from cls.blgpt import GPT

from cls.cmdsrvclass import ProcessCmd 
from cls.blacklist import IPBlacklist

from cls.typeclass import pkt,Hello,Host,ConnectionParam
from cls.scktclass import sckt

#encryption libraries
from cls.enc.dheclass import dhe 
from cls.enc.asymencclass import asymenc
from cls.enc.symencclass import symenc
from cls.enc.symencchaclass import symenccha
from cls.enc.helloclass import DHEHello

#utility functions for Server
from cls.srv import CustomFormatter, LogConfigure, ConfigRead , Logo, Logo2


global LoopQuit
global Blacklist
global server
global cnn
HOST = ""
PORT = 0
ENC = ""
PUBKEY = ""
PRIVKEY=""
LOGFILE = ""
LOGLEVELSCREEN=""
LOGLEVELFILE=""
logger= None

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  handle_client() <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

async def handle_client(client,address):
    global LoopQuit
    UMgr=""
    Usr=""
    SymEnc=None

    if LoopQuit:
    	return

    logger.info("========== Got connection from:" +str(address)+" ==========")

    loop = asyncio.get_event_loop()
    response=""
    request=b''
    tmp=b''
    size=0	
    Now=datetime.now().timestamp()

    while (request:=request + (tmp:= await loop.sock_recv(client, 8192))) and tmp!=b'' and len(request)>0 and not Blacklist.IsBlacklisted(address[0]):
    	try: 
	       	Now=datetime.now().timestamp()
	       	logger.info("START Message processing from: %s. %d bytes of %d",str(address), len(request), sckt.Size(request))
	       	if len(request)> 0 and sckt.Size(request)==0:
			#Message with wrong StartSentence (PKT)
		       	logger.error("		Incorrect message format!")
		       	Blacklist.DecreaseReputation(address[0])
	       		request=''

	       	while len(request)>= (size:=sckt.Size(request)) and sckt.Size(request)!=0:
	       		response=sckt.Parse(request,SymEnc)
	       		request=request[size:]

	       		if response.message==b'ERR':
		       		logger.error("		Error Decrypting message!")
		       		p= pkt("1","1","ERROR","NO", 1,b'Server error! Error Decrypting message!')
		       		await loop.sock_sendall(client, sckt.Build(p))
		       		Blacklist.DecreaseReputation(address[0])
		       		continue

		       	if isinstance(response, pkt):
#		       		logger.info("Got PKT from:	%s.",str(address))
		       		logger.info("	Got PKT:Type:%s, Encryption:%s, Size:%d bytes",response.ptype,response.enc,size)

		       		match response.ptype:
		       			case "Quit":
					       	LoopQuit=True
					       	logger.debug("Quit END")
					       	break

		       			case "CHello":
		       				logger.info("	CHello message from:%s",str(address))
		       				logger.info("	Init Encryption")
		       				ENC=str(DHEHello.GetEncryption(response.message))
		       				if ENC =="SYMAES":
		       					SymEnc=symenc() #Symmetric encryption AES
		       				elif ENC =="SYMCHA":
		       					SymEnc=symenccha() #Symmetric encryption CHA
		       				else:
		       					logger.error("		ERROR:Unsupported Encryption Type:%s",str(DHEHello.GetEncryption(response.message)))

				        		p= pkt("1","1","ERROR","NO", 1,b"ERROR:Unsupported Encryption Type!") #DHSYM
		       					await loop.sock_sendall(client, sckt.Build(p,SymEnc))

		       					break

		       				UMgr=UserManager(cnn)
		       				if not UMgr.IsReady(): 
		       					logger.error("		Database connection error!")
		       					p= pkt("1","1","ERROR","NO", 1,b'Server error! Database error.')
		       					await loop.sock_sendall(client, sckt.Build(p))
		       					continue

		       				err,ss,Usr =DHEHello.Server(UMgr,SymEnc,PRIVKEY,response.message)
		       				if int(err)<0 : 
		       					UMgr.Close()
		       					Blacklist.DecreaseReputation(address[0])
		       					errm=""
		       					if err==-1: errm=b'Invalid Public Key, or encryption method'
		       					if err==-2: errm=b'Invalid User name / password'
		       					if err==-3: errm=b'Private key error'
		       					p= pkt("1","1","ERROR","NO", 1,errm)
		       					await loop.sock_sendall(client, sckt.Build(p))
		       					logger.error("		DHEHello Error: "+errm.decode('utf-8'))

		       					continue
		       				logger.info("	User:"+Usr.username +"(ID:"+str(Usr.user_id) + ") connected.")

		       				logger.info("	SHello to:%s",str(address))
				        	p= pkt("1",HOST,"SHello","NO", 1,ss)
		       				await loop.sock_sendall(client, sckt.Build(p))
		       				
		       				logger.debug("		CHello END ")
		       				Blacklist.ResetReputation(address[0])

		       			case "CMD":
		       				logger.info("		CMD Message:%s",response.message.cmd)

		       				if SymEnc is None: 
		       					logger.error("		ERROR: Encryption is not ready!")
		       					break


		       				if UMgr.IsCommandAllowed(Usr.user_id,response.message.cmd): 
				        		ClassList={"UserManager":UMgr,"Test":Test(), "GPT":GPT()}
				        		response.message.args["UserName"]=Usr.username
#big question on the next line ??????????????
				        		response.message.args["MyUserId"]=Usr.user_id 

				        		ul = ProcessCmd.CallMethod(ClassList,response.message.cmd,response.message.args)

				        		p= pkt("1",HOST,'RESP',SymEnc.GetName(), 1,ul) 
		       					await loop.sock_sendall(client, ptmp:=sckt.Build(p,SymEnc))
		       					logger.info("	Send Responce PKT, Size:"+str(sys.getsizeof(ptmp)) +" bytes")
		       				else:
		       					logger.warning("		Command not allowed:%s User:%s",response.message.cmd,Usr.username)
	       						Blacklist.DecreaseReputation(address[0])

				        		p= pkt("1",HOST,"ERROR",SymEnc.GetName(), 1,b"Command not allowed!") #DHSYM
		       					await loop.sock_sendall(client, sckt.Build(p,SymEnc))
		       					logger.debug("		Send Response: ERROR!")
		       				logger.debug("		CMD END ")

		       			case _:
	       					Blacklist.DecreaseReputation(address[0])
					       	logger.warning("Unknown message type:%s done.",response.ptype)

        	logger.info("END Message processing (" + str(datetime.now().timestamp()-Now) +" seconds)\n")
    	except Exception as e:
        	logger.error("Server error! Handle client Error:%s", str(e) + "\n")
       		p= pkt("1",HOST,"ERROR","NO", 1,b'Server error! Handle client Error.')
	       	await loop.sock_sendall(client, sckt.Build(p))

    logger.info("========== Close connection from:"+str(address)+" ==========\n\n")
    UMgr.Close()


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> run_server() <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

async def run_server():
    global LoopQuit
    global Blacklist
    global server

    logger.info('Run server loop')
    Blacklist=IPBlacklist()
    try:
	    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    server.bind((HOST, PORT))
	    server.listen(8)
	    server.setblocking(False)
    except Exception as e:
    	logger.error("Server start error!:%s",str(e)+"\n")
    	exit()

    loop = asyncio.get_event_loop()
    while not LoopQuit:
        client, address = await loop.sock_accept(server)

        if not Blacklist.IsBlacklisted(address[0]) :
	        loop.create_task(handle_client(client,address))
        else:
        	logger.warning("Blacklisted IP:	%s connects. Rejected!",address[0])
        	client.shutdown(socket.SHUT_RDWR)
        	client.close() 



# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  MAIN()  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
if __name__ == '__main__':
#Read configuration file
    (HOST,PORT, ENC, PUBKEY, PRIVKEY, LOGFILE,LOGLEVELSCREEN,LOGLEVELFILE,cnn) = ConfigRead('./cfg/asgusrv.cfg')
#Configure logging
    logger=LogConfigure(LOGLEVELFILE,LOGLEVELSCREEN)

    os.system('clear')
    logger.info("Server initializaion (v.5.0).")	
    logger.info('Host:'+str( HOST)+'  Port:'+str(PORT)+ '  Encryption:' +str(ENC))
    Logo2()
    sleep(1)

    logger.info('<<<<<<<<<<<< Server started! >>>>>>>>>>>>')


    try:
    	LoopQuit = False
    	asyncio.run(run_server())
    except  KeyboardInterrupt:
    	print("CTRL-C pressed Async")
#    	server.close()
#    	server.close_clients()
#    	server.abort_clients()
    logger.info('>>>>>>>>>>>> Server shutdown! <<<<<<<<<<<<')
