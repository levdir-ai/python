from cls.dbl import UserManager, User
from cls.typeclass import pkt,Hello,Host,cmd, ConnectionParam
import inspect
from dataclasses import dataclass
from typing import Optional, List, Dict


@dataclass 
class ccmd:
	cmd: str
	user: str
	data: bytes
	args: Dict[str, any] #5 bytes


def call_method(o, name):
    return getattr(o, name)()

def IsValidMethod(MyClass,MethodName):
	method_list = []
	for attribute in dir(MyClass):
	    attribute_value = getattr(MyClass, attribute)
	    # Check that it is callable
	    if callable(attribute_value):
       	 # Filter all dunder (__ prefix) methods
	    	if attribute.startswith('__') == False:
	            method_list.append(attribute)
	            #print("Attr Name:",attribute, " ARGS:",inspect.getfullargspec(attribute_value).args)

	#print("ML:",method_list)
	return MethodName in method_list

#function call class method by method name and args dictionary
def CallClass(ClassList,CmdName,Args):
	ClassName,Method=CmdName.split('.') 	
#	print("Full command:",ClassName,Method) 
#	print("Full command:",type(ClassList[ClassName]))
	if Method in dir(ClassList[ClassName]):
		attribute_value = getattr(ClassList[ClassName], Method)
		t=()
		for c in inspect.getfullargspec(attribute_value).args:
			if (c!="self"):
				if c in Args: 
#					t=t+(Args[c],)
					print("Value:",c, "Val:", t:=t+(Args[c],))
				else:
					print("Not all ARGS:",c)
					return ""
		return getattr(ClassList[ClassName], Method)(*t)
	else:
#		print("No method")
		return ""


cnn = ConnectionParam(
    dbname="postgres",
    user="asgu",
    password="asgu",
    host="localhost"
)

q=ccmd("CMD","User",b'',{})
q.args["UserId"] = 2
q.args["Command"] = "GetList"
q.args["UserName"] = "dir"
q.args["Hsh"] = "asdsa"

manager = UserManager(cnn)
cl={"UserManager":manager}

cc=input("Command:UserManager.")
cc='UserManager.'+cc
#cc='UserManager.Get'
print("CMD:",cc)
#print ("Name:", type(cl["UserManager"]).__name__)
print("U:",u:=CallClass(cl,cc,q.args))
#u=(userId:=1,command:="GetList")
#print("U:",u)

#print(getattr(manager, func_name)(*u)) # Prints 2

#aa=call_method(manager, "GetList") 
#print("\nGetList:",aa)