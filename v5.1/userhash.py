import hashlib, uuid, sys

salt = uuid.uuid4().hex

if len(sys.argv)>1 :
	passw= sys.argv[1]
	ppwd=hashlib.sha512(passw.encode('utf-8')).hexdigest()
	print(ppwd)
else:
	passw=input("Enter password:")
	ppwd=hashlib.sha512(passw.encode('utf-8')).hexdigest()
	print("sha512 length(bytes):",len(ppwd))
	print("Hash:")
	print(ppwd)