import hashlib, uuid
salt = uuid.uuid4().hex
passw=input("Enter password:")
enc=passw
ppwd=hashlib.sha512(enc.encode('latin-1')).hexdigest()
print("Hash:\n",ppwd)
