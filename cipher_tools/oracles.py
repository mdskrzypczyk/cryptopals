from random import randint
from base64 import b64decode
from urllib.parse import quote
from cipher_tools.padding import *
from cipher_tools.encryption import encrypt_ecb, encrypt_cbc
from cipher_tools.decryption import decrypt_ecb, decrypt_cbc

def challenge11_oracle(data):
	block_size = 16
	key = bytes([randint(0,255) for i in range(block_size)])
	
	pre = bytes([randint(0,255) for i in range(randint(5,11))])
	app = bytes([randint(0,255) for i in range(randint(5,11))])

	choice = randint(0,2)
	if choice:
		iv = bytes([0]*block_size)
		return encrypt_ecb(iv, key, pre + data + app, pad=True)
	else:
		iv = bytes([randint(0,255) for i in range(block_size)])
		return encrypt_cbc(iv, key, pre + data + app, pad=True)

challenge12_key = bytes([randint(0,255) for i in range(16)])
def challenge12_oracle(data):
	with open('challenge_data/12.txt') as f:
		app = b64decode(f.read())
	data += app
	iv = bytes([0]*16)
	return encrypt_ecb(iv, challenge12_key, data, pad=True)

challenge14_rand = bytes([randint(0,255) for i in range(randint(0,31))])
challenge14_key = bytes([randint(0,255) for i in range(16)])
def challenge14_oracle(data):
	with open('challenge_data/12.txt') as f:
		app = b64decode(f.read())
	data = challenge14_rand + data + app
	iv = bytes([0]*16)
	return encrypt_ecb(iv, challenge14_key, data, pad=True)

challenge16_pre_data = quote("comment1=cooking%20MCs;userdata=", safe='%')
challenge16_post_data = quote(";comment2=%20like%20a%20pound%20of%20bacon", safe='%')
challenge16_key = bytes([randint(0,255) for i in range(16)])
def challenge16_oracle(data):
	wrapped_data = pkcs7pad(bytes(challenge16_pre_data + data + challenge16_post_data, 'utf-8'), 16)
	iv = bytes([0] * 16)
	return encrypt_cbc(iv, challenge16_key, wrapped_data, pad=True)

def challenge16_check_answer(cipher):
	iv = bytes([0] * 16)
	return b';admin=true;' in decrypt_cbc(iv, challenge16_key, cipher, pad=True)

challenge17_iv = bytes([randint(0,255) for i in range(16)])
challenge17_key = bytes([randint(0,255) for i in range(16)])
with open('challenge_data/17.txt') as f:
	strings = f.read().splitlines()
	random_string = bytes(strings[randint(0, len(strings) - 1)], 'utf-8')
def challenge17_oracle():
	padded_str = pkcs7pad(chosen_str, 16)
	return (iv, encrypt_cbc(iv, key, padded_str))