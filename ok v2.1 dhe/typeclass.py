from dataclasses import dataclass

@dataclass 
class pkt:
	source: str
	target: str
	ptype: str
	enc: bool
	seq: int
	message: bytes

#@dataclass
#class Address:
#    street: str
#    house_number: str
#    city: str
#    postal_code: str
#    country: str

# ?????? ?????????????
#address = Address("Main Street", "123", "New York", "10001", "USA")


