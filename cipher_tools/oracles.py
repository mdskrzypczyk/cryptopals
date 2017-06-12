from random import randint
from base64 import b64decode
from cipher_tools.encryption import encrypt_ecb, encrypt_cbc

def challenge11_oracle(data):
	key = bytes([randint(0,255) for i in range(16)])
	
	pre = bytes([randint(0,255) for i in range(randint(5,11))])
	app = bytes([randint(0,255) for i in range(randint(5,11))])

	choice = randint(0,2)
	if choice:
		iv = bytes([0]*16)
		print('ecb')
		return encrypt_ecb(iv, key, pre + data + app)
	else:
		iv = bytes([randint(0,255) for i in range(16)])
		print('cbc')
		return encrypt_cbc(iv, key, pre + data + app)

challenge12_key = bytes([randint(0,255) for i in range(16)])
def challenge12_oracle(data):
	with open('challenge_data/12.txt') as f:
		app = b64decode(f.read())
	data += app
	iv = bytes([0]*16)
	return encrypt_ecb(iv, challenge12_key, data)

challenge14_rand = bytes([randint(0,255) for i in range(randint(0,31))])
challenge14_key = bytes([randint(0,255) for i in range(16)])
def challenge14_oracle(data):
	with open('challenge_data/12.txt') as f:
		app = b64decode(f.read())
	data = challenge14_rand + data + app
	iv = bytes([0]*16)
	return encrypt_ecb(iv, challenge14_key, data)