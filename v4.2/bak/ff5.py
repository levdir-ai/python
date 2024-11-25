#import logging
#logger = logging.getLogger(__name__)
import curses
import socket
import time
import pickle
import os
import hashlib, uuid
import base64
import psycopg2


from cls.typeclass import pkt,Hello,Host,cmd
from cls.scktclass import sckt

from cls.asymencclass import asymenc
from cls.symencclass import symenc
from cls.dheclass import dhe 
from cls.dblcli import dhe 

def display_user_list(stdscr, user_manager):
    stdscr.clear()
    stdscr.box()
    users = user_manager
    
    # Display header
    stdscr.addstr(0, 2, "User List (Press 'q' to quit)", curses.A_BOLD)
    stdscr.addstr(2, 2, "ID   Full Name          Username         Last Login")
    
    for idx, user in enumerate(users):
        stdscr.addstr(idx + 3, 2, f"{user.user_id:<4} {user.full_name:<20} {user.username:<20} {user.last_login}")
    
    stdscr.refresh()
    
    # Wait for user selection
    while True:
        key = stdscr.getch()
        if key == ord('q') or key==27:
            break
        elif ord('1') <= key <= ord('8'):
            user_id = key - ord('1') + 1
            nw=curses.newwin(10,60,5,20)
            #display_user_details(nw, user_manager, user_id)
            del nw
            stdscr.touchwin()
            stdscr.refresh()


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server



#logging.basicConfig(filename='log/asguclient.log', level=logging.INFO, format='%(asctime)s: %(levelname)s:%(module)s.%(funcName)s: %(message)s')
#console_handler = logging.StreamHandler()
#logger.addHandler(console_handler)


print("Init ASYM Encryption")
mmenc=asymenc("cfg/pubkey.pem","")
print("	ENC ready:",mmenc.EncReady())
print("	DEC ready:",mmenc.DecReady())

print("Init SYM Encryption")
senc=symenc()
print("	Ready:",senc.Ready())
print("Init DHE Encryption")
d=dhe()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sct:
	try:
		sct.connect((HOST, PORT))
	except:
		print("Can't connect to:",HOST,":",PORT,"\nExit.")
		exit()


	usr=input("Enter user name (dir):")
	if usr=="": usr="dir"
	passw=input("Enter password:")
	ppwd=hashlib.sha512(passw.encode('latin-1')).hexdigest()

	d.GenerateKeys()
	s=Hello(Encrypted=Host(
			Random = os.urandom(16),
			User = usr,
			PHash = ppwd,
			AppName ="ASGU",
			AppVersion ="1.0",
			CertVersion = "DHE",
			DHCert = b'',
			IP=sckt.ip4_addresses(),
			Host=socket.gethostname(),
			),
			Encryption= os.urandom(16).hex(),
		Signature=b''
		)

	CliRandom=s.Encrypted.Random
	senc.Pass2Key(s.Encryption)
	s.Encrypted.DHCert=d.GetPublicKeyExp()
	s.Encrypted=senc.Encrypt(s.Encrypted)
	s.Encryption=mmenc.Encrypt(s.Encryption) #[10:] # broke the encrypted message

	p= pkt("1","1","CHello","PubKey,SYM", 1,s)
	sct.sendall(sckt.Build(p))

	data,sz = sckt.Parse(sct.recv(10000))

#    print(f"Received {data.ptype!r}")
	if data.ptype=="SHello":
		print("\nGot Hello from server")	
		ss=data.message
		print("Signature verification:",sign:=mmenc.Verify(ss.Encrypted,ss.Signature))
#    	print("Server CErt:",ss.Encrypted.DHCert)
		if sign :
			shared_key =d.Exchange(d.PublicKeyImp(ss.Encrypted.DHCert))
			senc.Pass2Key(ss.Encrypted.Random.hex()+shared_key.hex()+CliRandom.hex())
			print("Shared_key:",shared_key.hex()[:10],"....",shared_key.hex()[-10:])
			smsg=b" "
			print("SRV:",ss.Encrypted.Host,ss.Encrypted.Port, ss.Encrypted.IP)



#			cm=cmd("UserManager.GetList",usr,{"UserId":"1","Command":"UserManager.GetList"})
			cm=cmd("UserManager.GetList",usr,"")
			p= pkt("1","1","CMD","DHSYM", 1,cm)
			sct.sendall(tt:=sckt.Build(p,senc))
			data,sz = sckt.Parse(sct.recv(60000))

			display_user_list(stdscr := curses.initscr(), data.message)
			curses.endwin()

			while smsg!="":
				smsg=input("\nEnter command to send. Enter to Exit:")

				cm=cmd(smsg,usr,{"UserId":"2","Command":"GetList"})
				p= pkt("1","1","CMD","DHSYM", 1,cm)
				sct.sendall(tt:=sckt.Build(p,senc))

				data,sz = sckt.Parse(sct.recv(60000))

				print(f"Received {data.ptype!r}", data.message)

		else:
			print("Signature verification Failed")

	if data.ptype=="Error":
		print("\nGot Error from server:", data.message.decode('latin-1'))	
