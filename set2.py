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

from cipher_tools.oracles import challenge11_oracle
from cipher_tools.cracking import identify_oracle_encryption
def challenge11():
	return identify_oracle_encryption(challenge11_oracle)

from cipher_tools.oracles import challenge12_oracle
from cipher_tools.cracking import crack_challenge12_oracle
def challenge12():
	return crack_challenge12_oracle(challenge12_oracle)

def challenge13():
	pass

def challenge14():
	pass

from cipher_tools.padding import pkcs7pad_verify
def challenge15():
	pass

def challenge16():
	pass

