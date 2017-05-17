from cipher_tools.padding import pkcs7pad
def challenge9():
	data = b'YELLOW SUBMARINE'
	return pkcs7pad(data, 20)

from cipher_tools.decryption import decrypt_cbc
def challenge10():
	iv = bytes(16)
	key = b'YELLOW SUBMARINE'
	with open('challenge_data/12.txt') as f:
		data = f.read()
	return decrypt_cbc(iv, key, data)

def challenge11():
	pass

def challenge12():
	pass

def challenge13():
	pass

def challenge14():
	pass

from cipher_tools.padding import pkcs7pad_verify
def challenge15():
	pass

def challenge16():
	pass

