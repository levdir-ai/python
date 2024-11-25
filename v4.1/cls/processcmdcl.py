#import logging
#logger = logging.getLogger("main")
from cls.typeclass import cmd


class processCmd:

	def __init__(self):
		logger.info("Init Process CMD")
		self.public_key=""
		self.private_key=""
		self.shared_key=""


	def isItCMD(self, cm):
		return isinstance(cm, cmd)

	def runCMD(self, cm):
		return True
