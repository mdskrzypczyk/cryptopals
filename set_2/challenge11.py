from random import randint
from challenge10 import *

def gen_random_16():
	return bytes([randint(0,255) for i in range(16)])

def encryption_oracle(data):
	key = gen_random_16()
	
	pre = bytes([randint(0,255) for i in range(randint(5,11))])
	app = bytes([randint(0,255) for i in range(randint(5,11))])

	choice = randint(0,2)
	if choice:
		iv = bytes([0]*16)
		return encrypt_ecb(iv, key, pre + data + app)
	else:
		iv = gen_random_16()
		return encrypt_cbc(iv, key, pre + data + app)

def detect_encryption(enc_func):
	test_data = bytes([0]*44)
	encrypted = enc_func(test_data)
	blocks = breakup_cipher(encrypted, 16)
	if len(set(blocks)) < len(blocks):
		return 'ecb'
	else:
		return 'cbc'

#print(detect_encryption(encryption_oracle))