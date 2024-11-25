#import logging
#logger = logging.getLogger(__name__)

import socket
import time
import pickle
import os
import hashlib, uuid
import base64
import psycopg2
from getpass import getpass

from cls.typeclass import pkt,Hello,Host,cmd
from cls.scktclass import sckt

#from cls.asymencclass import asymenc
from cls.symencclass import symenc
#from cls.dheclass import dhe 
from cls.helloclass import DHEHello


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server

#logging.basicConfig(filename='log/asguclient.log', level=logging.INFO, format='%(asctime)s: %(levelname)s:%(module)s.%(funcName)s: %(message)s')
#console_handler = logging.StreamHandler()
#logger.addHandler(console_handler)

#==================================== MAIN ===============================
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
	try:
		sct.connect((HOST, PORT))
	except:
		print("Can't connect to:",HOST,":",PORT,"\nExit.")
		exit()

	usr=input("Enter user name (dir):")
	if usr=="": usr="dir"
	passw=input("Enter password:")

	senc,errm=DHEHello.Client(sct,usr,passw,"cfg/pubkey.pem")	
	if errm!="": 
		print("Error:", errm.decode("latin-1"), "\nExit.")
		exit()
	smsg=b" "

	while smsg!="":
		smsg=input("\nEnter command to send. Enter to Exit:UserManager.")
		cm=cmd("UserManager."+smsg,usr,{"UserId":"2",
										"Command":"GetList",
										"Hsh":"4b0ab7b94e92a4f175774a4ad8a9a8c4d273671086ef091a689d63d3752a53ba043a1daf6204c9d4043b24bb42e18903029b43acd5efeabf7f368c26d532ab6e",
										"UserName":"dir"})
		p= pkt("1","1","CMD","DHSYM", 1,cm)
		sct.sendall(tt:=sckt.Build(p,senc))

		data,sz = sckt.Parse(sct.recv(60000))

		print(f"Received {data.ptype!r}", data.message)

	if data.ptype=="Error":
		print("\nGot Error from server:", data.message.decode('latin-1'))	
