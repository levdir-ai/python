import configparser
from datetime import datetime
from getpass import getpass
import hashlib, uuid
import os
import psycopg2
import socket

import textwrap
import jsonpickle
import re

from cls.typeclass import pkt,cmd
from cls.scktclass import sckt

#encryption libraries
from cls.enc.symencclass import symenc
from cls.enc.symencchaclass import symenccha
from cls.enc.helloclass import DHEHello

help="""
H:			Help, 
D:Class			Set default Class, 
P:			Print parameters for remote calls,
S:Var:Value		Set Value for parameter Var,
Cmd.ClassList   	Classes list,
CLASSNAME.CmdList       Commands/methods list for CLASSNAME
CLASSNAME.ParamList     Parameters list for the command selected by S:Command:COMMANDNAME
"""

config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
config.read('./cfg/asgucli.cfg')

try:
	HOST = config.get('Connection','Host')  # The server's hostname or IP address
	PORT = config.getint('Connection','Port')   # The port used by the server
	ENC= config.get('Connection','Encryption')	
	PUBKEY = config.get('Other','PublicKey')
	LOGFILE = config.get('Other','LogFile')
except Exception as err:
	print("Configuration error:",err)
	exit()

#==================================== MAIN ===============================
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
	try:
		sct.connect((HOST, PORT))
	except:
		print("Can't connect to:",HOST,":",PORT,"\nExit.")
		exit()

	usr=input("\nEnter user name (dir):")
	if usr=="": usr="dir"
	passw=getpass("Enter password:")

	print("\nInit SYM Encryption")
	if ENC =="SYMAES":
		SymEnc=symenc() #Symmetric encryption AES
	elif ENC =="SYMCHA":
		SymEnc=symenccha() #Symmetric encryption CHA
	else:
		print("		ERROR:Unsupported Encryption Type:",ENC)
		exit()

	print(" 	"+ENC+ " encryption enabled.")
	print("	Ready:",SymEnc.Ready())

	Now=datetime.now().timestamp()
	errm=DHEHello.Client(sct,SymEnc,usr,passw,PUBKEY)	
	print("CHello processing time:" + str(datetime.now().timestamp()-Now) +" s\n")

	if errm!="": 
		print("Error:", errm.decode("utf-8"), "\nExit.")
		exit()
	smsg=b" "
	clsname=""
	CmdParam={"Command":"GetList","Now":"","UserId":2, "FileName":""}

	print("\nEnter command to send. Enter to Exit. H: to help.")
	while smsg!="":
		smsg=input("\nSend command:"+clsname)
		if match := re.match(r"(\w+.\w+)\((.*?)\)", smsg): 
			smsg = match.group(1)
			params_str = match.group(2)
			params = {}
			if params_str:
				for param in params_str.split(','):
					key, value = re.split(':|=', param)
					CmdParam[key.strip()] = value.strip()
		if smsg=="": 
			print("Exit.")
			break

		if smsg[:2]=="D:": 
			if smsg[2:]=="": 
				clsname=""
			else: 
				clsname=smsg[2:]+"."
			continue

		if smsg[:2]=="H:": 
			print(help)
			continue

		if smsg[:2]=="P:": 
			print("Params:", CmdParam)
			continue

		if smsg[:2]=="S:": 
			tmp=smsg[2:].split(':')
			if len(tmp)==2:
				CmdParam[tmp[0]]=tmp[1]
				print("Set:",tmp)
			else:
				print("Error!!! Set:",smsg)
			continue

		CmdParam["Now"]=datetime.now().timestamp()
		if CmdParam["FileName"]!="":
			try:
				with open(CmdParam["FileName"], "r", encoding="utf-8") as file: #, encoding="utf-8" "rb"
					CmdParam["FileData"] = file.read()
				_, fname = os.path.split(CmdParam["FileName"])
				CmdParam["FileName"]=fname

			except:
				print("Error opening file:", CmdParam["FileName"])

			#CmdParam["File"]='1234567890'*500

		cm=cmd(clsname+smsg,usr,CmdParam)

		p= pkt("1",HOST,"CMD",ENC, 1,cm) #DHSYM
		sct.sendall(sckt.Build(p,SymEnc))
		data = sckt.Parse(sct.recv(60000),SymEnc)

		CmdParam["FileName"]=""
		CmdParam["FileData"]=""

		if data.ptype=="ERROR":
			print("Got Error from server:", data.message.decode('utf-8'))	
		else:
			print("Response ("+str(data.seq)+"):")
			if str(data.message).count('\n')>0:
				print(str(data.message))
			else:
				print(textwrap.indent( textwrap.fill(str(data.message), width=80),  ' '*16))

