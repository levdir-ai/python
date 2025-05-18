from datetime import datetime
import random
import psutil

pic=(
"""
                       /)
              /\___/\ ((
    -----------------------------
    The cat is hiding, try again!
""",
"""
                       /)
              /\___/\ ((
              \`@_@'/  ))
              {_:Y:.}_//
    ----------{_}^-'{_}----------
""",
"""
                       /)
              /\___/\ ((
    -----------------------------
    The cat is hiding, try again!
""",
"""
      |\      _,,,---,,_
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_) 
""",
"""
                       /)
              /\___/\ ((
    -----------------------------
    The cat is hiding, try again!
""",
"""
           .'\   /`.
         .'.-.`-'.-.`.
    ..._:   .-. .-.   :_...
  .'    '-.(o ) (o ).-'    `.
 :  _    _ _`~(_)~`_ _    _  :
:  /:   ' .-=_   _=-. `   ;\  :
:   :|-.._  '     `  _..-|:   :
 :   `:| |`:-:-.-:-:'| |:'   :
  `.   `.| | | | | | |.'   .'
    `.   `-:_| | |_:-'   .'
      `-._   ````    _.-'
          ``-------''
""",
"""
                       /)
              /\___/\ ((
    -----------------------------
    The cat is hiding, try again!
""",
"""
 ._       __          ____
;  `\--,-' /`)    _.-'    `-._
 \_/    ' | /`--,'            `-.     .--....____
  /                              `._.'           `---...
  |-.   _      ;                        .-----..._______)
,,\q/ (q_>'_...                      .-'
===/ ; _.-'~~-             /       ,'
`''`-'_,;  `''         ___(       |
         \         ; /'/   \      \ 
          `.      //' (    ;`\    `\ 
          / \    ;     `-  /  `-.  /
         (  (;   ;     (__/    /  /
          \,_)\  ;           ,'  /
  .-.          |  |           `--'
 ("_.)-._     (__,>    

""")

class Test:
    def Test(self, UserId,Command):
        return "Test:UserID:"+str(UserId)+" CommandName:"+Command

    def CmdList(self):
        return list(filter(lambda x: x[:2]!='__', dir(self)))

    def Ping(self,Now):
        return "Pong:"+str(datetime.now().timestamp()-Now) +" seconds"

    def Pong(self,Now):
        return "Ping!!! :"+str(datetime.now().timestamp()-Now) +" seconds"

    def Hello(self, MyUserId,UserName):
        return "Hello:MyUserID:"+str(MyUserId)+" UserName:"+ UserName

    def ID(self, MyUserId,UserName, UserId):
        return "ID:MyUserID:"+str(MyUserId)+" UserId:"+ str(UserId)

    def Cat(self):
        return pic[random.randint(0,len(pic)-1)]

    def Cats(self):
        return pic[1]+pic[3]+pic[5]+pic[7]

    def Lev(self,name,soname):
        return "My name is "+name +". My soname is:" + soname


    def Msg(self,Msg,UserName):
        print("\n\n	Message from:" +UserName+ ":"+Msg+"\n\n")
        return "Message recived"

    def Info(self):
        return {"Memory": psutil.virtual_memory(),"CPU":psutil.cpu_times(),"Disk":psutil.disk_usage('/'),"Net 1":psutil.net_if_stats()} #,"Net 2": psutil.net_if_addrs()}

    def SendFile(self,FileName,FileData):
        print("\n File name:"+FileName+" size:" +str(len(FileData)))
        print("\n<<<<<<<<< File begin >>>>>>>>>\n",FileData, "\n<<<<<<<<<< File end >>>>>>>>>>\n")
        with open("./log/"+FileName, "a", encoding="utf-8") as file: #, encoding="utf-8" , "ab"
        	file.write(FileData)
        return "File recived:"+FileName+" size:" +str(len(FileData))
