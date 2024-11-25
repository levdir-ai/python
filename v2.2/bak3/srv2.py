import asyncio, socket
import base64
import pickle
import sys
import os

from cls.typeclass import pkt
from cls.scktclass import sckt

from cls.dheclass import dhe 
from cls.asymencclass import asymenc
from cls.symencclass import symenc

from cls.ClientHello import ClientHello,Client

global LoopQuit

async def handle_client(client,address):
    global LoopQuit
    if LoopQuit:
    	return

    print("======================= Get connection from:",address," =========================")
    print("Init Encryption")
    print("Init DHE")
    d=dhe()
    d.GenerateKeys()

    print("Init ASYM")
    mmenc=asymenc("cfg/pubkey.pem","cfg/privkey.pem")
    print("	ENC ready:",mmenc.EncReady())
    print("	DEC ready:",mmenc.DecReady())

    print("Init SYM\n")
    senc=symenc()

    loop = asyncio.get_event_loop()
    response=""
    p= pkt("1","1","OK","", 1,b'')
    while (request:= (await loop.sock_recv(client, 4096))) and len(request)>0:
    	try: 
	       	print("\nGot Message. Size:", len(request))
	       	#print("Message", len(request)," Body:\n",request.decode('latin-1'))
	       	while len(request)>1:
	       		(response,size)=sckt.parse(request,senc)
#	       		size= int(request[4])+int(request[3]*256)
#	       		response = pickle.loads(request[5:size])

	       		#print("\nPKT Size:",size,"Type:",response.ptype,"\n") #," Body:\n",request[:size].decode('latin-1'),"\n\n")
	       		request=request[size:]

		       	if isinstance(response, pkt):
		       		print("Got PKT.	Type:",response.ptype," Encryption:",response.enc)
		       		match response.ptype:
		       			case "Quit":
					       	LoopQuit=True
#				       	p= pkt("1","1","OK",False, 1,b' ')
#				       	await loop.sock_sendall(client, pickle.dumps(p))
					       	print("Quit: done")
		       			case "CHello":
		       				print("		CHello")
		       				pkk=d.PublicKeyImp(response.message)
		       				shared_key =d.Exchange(pkk)
		       				#print("Shared_key:",base64.b64encode(shared_key).decode('utf-8'))


				        	pk=d.GetPublicKeyExp()
				        	p= pkt("1","1","SHello","", 1,pk)
		       				await loop.sock_sendall(client, sckt.build(p))


		       			case "CHello1":
		       				print("		CHello1")

		       				s=response.message
		       				#pkk=d.PublicKeyImp(response.message)
		       				#shared_key =d.Exchange(pkk)
		       				#print("Shared_key:",base64.b64encode(shared_key).decode('utf-8'))
		       				s.Encryption=mmenc.decrypt(s.Encryption)
		       				print("		DEcrypt:",s.Encryption)
		       				if s.Encryption==-1: 
		       					print("		Invalid Public Key! Exit.")
		       					p= pkt("1","1","Error","", 1,b'Invalid Public Key')
		       					await loop.sock_sendall(client, sckt.build(p))
		       					continue
		       				else: print("		Valid Public Key!") 				
		       				#print("\n",s)
		       				senc.pass2key(s.Encryption)
		       				s.Encrypted=senc.decrypt(s.Encrypted)
		       				#print("\nClient CERT:",s.Encrypted.DHCert)

		       				k=d.Exchange(d.PublicKeyImp(s.Encrypted.DHCert))
		       				print("		Shared_Key:\n",k.hex())
		       				senc.pass2key(k.hex())

		       				print("\n		SHello1")

		       				ss=ClientHello(Encrypted=Client( 
							Random = os.urandom(16),
							UserHash = b'',
							AppName ="ASGU",
							AppVersion ="1.0",
							CertVersion = "DHE",
							DHCert = d.GetPublicKeyExp(),
							IP=sckt.ip4_addresses(),
							Host=socket.gethostname(),
							),
							Encryption= b'None',
							Signature=b''
						)
		       				ss.Signature=mmenc.sign(ss.Encrypted)

		       				#print("Server Cert:",ss.Encrypted.DHCert)

				        	p= pkt("1","1","SHello1","", 1,ss)
		       				await loop.sock_sendall(client, sckt.build(p))

		       				print("		EXIT CHello1")

		       			case "Data":
		       				print("		Data")
		       				#s=senc.decrypt(response.message)
		       				#pkk=d.PublicKeyImp(response.message)
		       				#shared_key =d.Exchange(pkk)
		       				#print("Shared_key:",base64.b64encode(shared_key).decode('utf-8'))
		       				print("		Message:",response.message.decode('latin-1'))
		       				#p= pkt("1","1","Data",True, 1,smsg)
		       				#sct.sendall(sckt.build(p,senc))



		       			case "Test":
#				       	p= pkt("1","1","OK",False, 1,b' ')
#				       	await loop.sock_sendall(client, pickle.dumps(p))
					       	print("Test: done")
		       			case _:
					       	print("Unknown type:",response.ptype," done")
	
		
        	print("Exit Message","\n")
    	except Exception as e:
        	print("handle client Error:", e,"\n")
        	await loop.sock_sendall(client, b'Error')
	       	req="quit"
    print("========================== Close connection from:",address," ===========================\n")
    #client.close()

async def run_server():
    global LoopQuit

    print("Run server")	
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 15555))
    server.listen(8)
    server.setblocking(False)

    loop = asyncio.get_event_loop()
    while not LoopQuit:
#        print("----LoopQuit:",LoopQuit)
        client, address = await loop.sock_accept(server)
#        print("----Loop1:",LoopQuit)
        loop.create_task(handle_client(client,address))
#        print("----Loop2:", LoopQuit)



print("Server initializaion.")	
try:
	LoopQuit = False
	asyncio.run(run_server())
except  KeyboardInterrupt:
	print("CTRL-C pressed Async")
print("Exit Server")	