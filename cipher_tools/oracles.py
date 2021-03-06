import time
import base64
from random import randint, choice
from base64 import b64decode
from urllib.parse import quote
from zlib import compress
from functools import partial
from cipher_tools.data_manipulation import breakup_data
from cipher_tools.rng import mersenne_twister_rng, MT19937_config
from cipher_tools.padding import *
from cipher_tools.mathlib import gen_rsa_keys
from cipher_tools.encryption import encrypt_ecb, encrypt_cbc, encrypt_ctr, encrypt_mersenne, encrypt_rsa
from cipher_tools.decryption import decrypt_ecb, decrypt_cbc, decrypt_ctr, decrypt_rsa

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

challenge26_pre_data = bytes(quote("comment1=cooking%20MCs;userdata=", safe='%'), 'utf-8')
challenge26_post_data = bytes(quote(";comment2=%20like%20a%20pound%20of%20bacon", safe='%'), 'utf-8')
challenge26_key = bytes([randint(0,255) for i in range(16)])
def challenge26_oracle(data):
	wrapped_data = pkcs7pad(challenge26_pre_data + data + challenge26_post_data, 16)
	iv = bytes([0] * 16)
	return encrypt_ctr(iv, challenge26_key, wrapped_data)

def challenge26_check_answer(cipher):
	iv = bytes([0] * 16)
	data = decrypt_ctr(iv, challenge26_key, cipher)
	return b';admin=true' in data

challenge27_pre_data = bytes(quote("comment1=cooking%20MCs;userdata=", safe='%'), 'utf-8')
challenge27_post_data = bytes(quote(";comment2=%20like%20a%20pound%20of%20bacon", safe='%'), 'utf-8')
challenge27_key = bytes([randint(0,255) for i in range(16)])
class Exception_challenge27(Exception):
	def __init__(self, data):
		self.data = data

def challenge27_oracle(data):
	if any([d > 0x7F for d in data]):
		raise Exception_challenge27(data=data)

	wrapped_data = pkcs7pad(challenge27_pre_data + data + challenge27_post_data, 16)
	iv = challenge27_key
	return encrypt_cbc(iv, challenge27_key, wrapped_data, pad=True)

def challenge27_check_answer(cipher):
	iv = challenge27_key
	data = decrypt_cbc(iv, challenge27_key, cipher, pad=False)
	if any([d > 0x7F for d in data]):
		raise Exception_challenge27(data=data)
	return b';admin=true' in data

challenge46_pub, challenge46_priv = gen_rsa_keys()
challenge46_cipher = encrypt_rsa(base64.b64decode(open('challenge_data/46.txt').read()),
								 challenge46_pub[0], challenge46_pub[1])
def challenge46_oracle(cipher):
	data = decrypt_rsa(cipher, challenge46_priv[0], challenge46_priv[1])
	return (int.from_bytes(data, 'big') & 0x1)

challenge47_pub, challenge47_priv = gen_rsa_keys(256)
challenge47_cipher = encrypt_rsa(pkcs1v15pad(b"kick it, CC", 256), challenge47_pub[0], challenge47_pub[1])
def challenge47_oracle(cipher):
	data = decrypt_rsa(cipher, challenge47_priv[0], challenge47_priv[1])
	if len(data) == 31:
		data = b'\x00' + data
	return data[0] == 0 and data[1] == 2

challenge48_pub, challenge48_priv = gen_rsa_keys(768)
challenge48_cipher = encrypt_rsa(pkcs1v15pad(b"kick it, CC", 768), challenge48_pub[0], challenge48_pub[1])
def challenge48_oracle(cipher):
	data = decrypt_rsa(cipher, challenge48_priv[0], challenge48_priv[1])
	if len(data) == 95:
		data = b'\x00' + data
	return data[0] == 0 and data[1] == 2

def challenge51_oracle(p, enc_func):
	plaintext = "POST / HTTP/1.1\n" \
				"Host: hapless.com\n" \
				"Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n" \
				"Content-Length: {}\n" \
				"{}".format(len(p), p)
	iv = bytes([randint(0,255) for _ in range(16)])
	key = bytes([randint(0,255) for _ in range(16)])
	return len(enc_func(iv, key, compress(bytes(plaintext, 'utf-8'), level=9)))

challenge52_iv = bytes(randint(0,255) for _ in range(16))
challenge52_key = bytes(randint(0,255) for _ in range(16))
challenge52_h = b'\x00'
def challenge52_f(m, c=partial(encrypt_ecb, pad=False), h=challenge52_h):
	hash = int.from_bytes(h, 'big')

	for m_i in breakup_data(pkcs7pad(m, 16), 16):
		hash += int.from_bytes(c(challenge52_iv, challenge52_key, m_i), 'big')

	return hash.to_bytes(len(h), 'big')

def challenge52_g(m, c=encrypt_cbc, h=challenge52_h*3):
	hash = int.from_bytes(h, 'big')

	for m_i in breakup_data(pkcs7pad(m, 16), 16):
		hash += int.from_bytes(c(challenge52_iv, challenge52_key, m_i, False), 'big')
		hash %= (2**(len(h) * 8))

	return hash.to_bytes(len(h), 'big')

def challenge52_oracle(m, f=challenge52_f, g=challenge52_g):
	return f(m=m) + g(m=m)

challenge53_iv = bytes(randint(0,255) for _ in range(16))
challenge53_key = bytes(randint(0,255) for _ in range(16))
def challenge53_hasher(m, h=b'\x00'):
	hash = int.from_bytes(h, 'big')

	for m_i in breakup_data(m, len(h)):
		h_i = encrypt_ctr(challenge53_iv, challenge53_key, m_i)
		hash += int.from_bytes(h_i, 'big')
		hash %= (2 ** (len(h) * 8))

	return hash.to_bytes(len(h), 'big')
