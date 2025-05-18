import logging
logger = logging.getLogger("main")

from cls.typeclass import pkt,cmd
from cls.scktclass import sckt


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
			return "Error:Bad command format:" +CmdName

		cm=cmd(CmdName,self.usr,Args)
		p= pkt("1","1","CMD","SYM", 1,cm) #DHSYM
		self.sct.sendall(sckt.Build(p,self.senc))
		dat=self.sct.recv(60000)

		if sckt.Size(dat)>0 :
			data = sckt.Parse(dat,self.senc)
			return data.message

