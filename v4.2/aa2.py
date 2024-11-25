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
from getpass import getpass

from cls.typeclass import pkt,Hello,Host,cmd
from cls.scktclass import sckt

from cls.asymencclass import asymenc
from cls.symencclass import symenc
from cls.dheclass import dhe 
from cls.cmdcliclass import ProcessCmd

def display_user_list(stdscr, PCmd):
    stdscr.clear()
    stdscr.box()
    users = PCmd.CallRemoteCmd("UserManager.GetList","")

    # Display header
    stdscr.addstr(0, 2, "User List (Press User ID number or press 'q' to quit)", curses.A_BOLD)
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
            nw=curses.newwin(15,60,5,20)
            display_user_details(nw, PCmd, user_id)
            del nw
            stdscr.touchwin()
            stdscr.refresh()

def display_user_details(stdscr, PCmd, user_id):
    stdscr.clear()
    stdscr.box()
    #stdscr.bkgd(' ', curses.color_pair(1) | curses.A_BOLD | curses.A_REVERSE)
    user = PCmd.CallRemoteCmd("UserManager.Get",{"UserId":user_id})
    
    if user:
        stdscr.addstr(0, 2, f"User Details for {user.username} (Press 'b' to go back)", curses.A_BOLD)
        stdscr.addstr(2, 2, f"ID: {user.user_id}")
        
        # Display current values
        stdscr.addstr(3, 2, f"Full Name: {user.full_name}")
        stdscr.addstr(4, 2, f"Email: {user.email}")
        stdscr.addstr(5, 2, f"Created At: {user.created_at}")
        stdscr.addstr(6, 2, f"Last Login: {user.last_login}")

        
        # Create input fields for editing
        stdscr.addstr(7, 2, "Edit Full Name   :")

        full_name_input = user.full_name
        stdscr.addstr(7, 20, full_name_input.ljust(30))
        stdscr.move(7, 20 + len(full_name_input))
        
        while True:
            key = stdscr.getch()
            if key == curses.KEY_BACKSPACE or key == 127:  # Handle backspace
                full_name_input = full_name_input[:-1]
            elif key == ord('\n'):  # Enter key to finish input
                break
            elif key == 27:  # ESC key to cancel
                return user
            else:
                full_name_input += chr(key)  # Add character to input
            stdscr.addstr(7, 20, full_name_input.ljust(30))  # Display input
            stdscr.move(7, 20 + len(full_name_input))  # Move cursor to end of input
        
        stdscr.addstr(8, 2,"Edit Email       :")

        email_input = user.email
        stdscr.addstr(8, 20, email_input.ljust(30))  # Display input
#        stdscr.clrtoeol()  # Clear to end of line
        stdscr.move(8, 20 + len(email_input))  # Move cursor to end of input
        
        while True:
            key = stdscr.getch()
            if key == curses.KEY_BACKSPACE or key == 127:  # Handle backspace
                email_input = email_input[:-1]
            elif key == ord('\n'):  # Enter key to finish input
                break
            elif key == 27:  # ESC key to cancel
                return user
            else:
                email_input += chr(key)  # Add character to input
            stdscr.addstr(8, 20, email_input.ljust(30))  # Display input
#            stdscr.clrtoeol()  # Clear to end of line
            stdscr.move(8, 20 + len(email_input))  # Move cursor to end of input
        
        # Update user object with new values
        user.full_name = full_name_input if full_name_input else user.full_name
        user.email = email_input if email_input else user.email
        p = PCmd.CallRemoteCmd("UserManager.Save",{"UserId":user_id,"user":user})
        
        stdscr.addstr(9, 2, "User updated successfully! Press 'b' to go back.")
    else:
        stdscr.addstr(2, 2, "User not found.")
    
    stdscr.refresh()
    
    while True:
        key = stdscr.getch()
        if key == ord('b') or key == 27:  # 'b' or ESC to go back
            break
    
    return user  # Return the updated user object



HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 15555  # The port used by the server

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
	passw=getpass("Enter password:")
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
			PCmd=ProcessCmd(sct,senc, usr)

#			data,sz = sckt.Parse(sct.recv(60000))

			display_user_list(stdscr := curses.initscr(),PCmd)
			curses.endwin()


		else:
			print("Signature verification Failed")

	if data.ptype=="Error":
		print("\nGot Error from server:", data.message.decode('latin-1'))	
