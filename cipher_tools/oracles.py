import time
from random import randint, choice
from base64 import b64decode
from urllib.parse import quote
from cipher_tools.rng import mersenne_twister_rng, MT19937_config
from cipher_tools.padding import *
from cipher_tools.encryption import encrypt_ecb, encrypt_cbc, encrypt_ctr, encrypt_mersenne
from cipher_tools.decryption import decrypt_ecb, decrypt_cbc, decrypt_ctr

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
challenge17_cipher = encrypt_cbc(challenge17_iv, challenge17_key,
								 bytes(choice(open('challenge_data/17.txt').read().splitlines()), 'utf-8'),
								 pad=True)
def challenge17_oracle(iv_cipher):
	decrypted = decrypt_cbc(iv_cipher[0], challenge17_key, iv_cipher[1], pad=False)
	block_size = len(iv_cipher[0])
	return pkcs7pad_verify(decrypted, block_size)

challenge19_nonce = bytes(16)
challenge19_key = bytes([randint(0, 15) for i in range(16)])
challenge19_dataset = [b64decode(data) for data in open('challenge_data/19.txt').read().splitlines()]
def get_challenge19_cipherset():
	return [encrypt_ctr(challenge19_nonce, challenge19_key, data) for data in challenge19_dataset]

challenge20_nonce = bytes(16)
challenge20_key = bytes([randint(0, 255) for i in range(16)])
challenge20_dataset = [b64decode(data) for data in open('challenge_data/20.txt').read().splitlines()]
def get_challenge20_cipherset():
	return [encrypt_ctr(challenge20_nonce, challenge20_key, data) for data in challenge20_dataset]

def challenge22_oracle():
	delay = randint(40, 1000)
	time.sleep(delay)
	seed = int(time.time())
	val = mersenne_twister_rng(seed, MT19937_config, 0)
	delay = randint(40, 1000)
	time.sleep(delay)
	return val

challenge24_seed = randint(0, 2**16 - 1)
challenge24_pre = bytes([randint(0, 255) for i in range(randint(0,400))])
def challenge24_oracle(plaintext):
	return encrypt_mersenne(challenge24_seed, challenge24_pre + plaintext, MT19937_config)

challenge25_iv = bytes([randint(0, 255) for i in range(16)])
challenge25_key = bytes([randint(0, 255) for i in range(16)])
def challenge25_oracle():
	with open("challenge_data/25.txt") as f:
		data = decrypt_ecb(bytes(16), b"YELLOW SUBMARINE", b64decode(f.read()), pad=True)
	return encrypt_ctr(challenge25_iv, challenge25_key, data)

def challenge25_edit(ciphertext, offset, newtext, key=challenge25_key):
	decrypted = decrypt_ctr(challenge25_iv, key, ciphertext)
	return encrypt_ctr(challenge25_iv, key, decrypted[:offset] + newtext)

challenge26_pre_data = quote("comment1=cooking%20MCs;userdata=", safe='%')
challenge26_post_data = quote(";comment2=%20like%20a%20pound%20of%20bacon", safe='%')
challenge26_key = bytes([randint(0,255) for i in range(16)])
def challenge26_oracle(data):
	wrapped_data = pkcs7pad(bytes(challenge16_pre_data + data + challenge16_post_data, 'utf-8'), 16)
	iv = bytes([0] * 16)
	return encrypt_ctr(iv, challenge16_key, wrapped_data, pad=True)

def challenge26_check_answer(cipher):
	iv = bytes([0] * 16)
	return b';admin=true;' in decrypt_ctr(iv, challenge16_key, cipher, pad=True)