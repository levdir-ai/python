import inspect
import logging
logger = logging.getLogger("main")


class ProcessCmd:

#function call class method by method name and args dictionary
	def CallMethod(ClassList,CmdName,Args):
		if CmdName.find('.')!=-1 : 
			ClassName,Method=CmdName.split('.')
		else:
			logger.error ("Bad command format:" +CmdName)
			return ""

		if not ClassName in ClassList: 
			logger.error ("Class '"+ ClassName +"' not exist!")
			return ""

		if Method in dir(ClassList[ClassName]): # Validate existence of the method
			attribute_value = getattr(ClassList[ClassName], Method)
			t=()
			for c in inspect.getfullargspec(attribute_value).args:
				if (c!="self"):
					if c in Args:
						t=t+(Args[c],)
					else:
						logger.error("Not all required ARGS provided:"+c)
						return ""
			return getattr(ClassList[ClassName], Method)(*t)
		else:
			logger.error ("Class '"+type(ClassList[ClassName]).__name__+"' have no method '"+ Method+"'")
			return ""


