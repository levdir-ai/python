import inspect
import logging
logger = logging.getLogger("main")
 
import socket
import time
import pickle
import os
import hashlib, uuid
import base64
import psycopg2


from cls.typeclass import pkt,cmd
from cls.scktclass import sckt

#from cls.asymencclass import asymenc
#from cls.symencclass import symenc

class ProcessCmd:
	def __init__(self, sct,senc,usr):
		self.sct=sct
		self.senc=senc
		self.usr=usr

    	#function call class method by method name and args dictionary
	def CallRemoteCmd(self,CmdName,Args):
		if CmdName.find('.')!=-1 : 
			ClassName,Method=CmdName.split('.')
		else:
			logger.error ("Bad command format:" +CmdName)
			return ""

		cm=cmd(CmdName,self.usr,Args)
		p= pkt("1","1","CMD","DHSYM", 1,cm)
		self.sct.sendall(tt:=sckt.Build(p,self.senc))
		data,sz = sckt.Parse(self.sct.recv(60000))
		if sz>0 :
			return data.message