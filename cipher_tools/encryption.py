from Crypto.Cipher import AES
from cipher_tools.rng import mersenne_twister_rng
from cipher_tools.padding import pkcs7pad
from cipher_tools.data_manipulation import breakup_data

def encrypt_ecb(iv, key, data, pad):
	block_size = len(key)
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/block_size), data)])
	if pad:
		data = pkcs7pad(data, block_size)
	return aes.encrypt(data)


def encrypt_cbc(iv, key, data, pad):
	block_size = len(key)
	if pad:
		data = pkcs7pad(data, block_size)
	data_blocks = breakup_data(data, block_size)
	cipher = bytes('', 'utf-8')
	for b in data_blocks:
		enc_b = encrypt_ecb(iv, key, b, pad=False)
		cipher += enc_b
		iv = enc_b

	return cipher

def gen_ctr_key_stream(key, data):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	return aes.encrypt(data)

def encrypt_ctr(nonce, key, data):
	data_blocks = breakup_data(data, 16)

	cipher = b''
	counter = int.from_bytes(nonce, 'big')
	for block in data_blocks:
		key_stream = gen_ctr_key_stream(key, nonce)
		enc_b = bytes([k^d for k,d in zip(key_stream, block)])
		cipher += enc_b

		counter += 72057594037927936
		nonce = counter.to_bytes(16, 'big')

	return cipher

def encrypt_mersenne(seed, data, config):
	if seed > 2**16 - 1:
		raise Exception('seed must be 16 bits')

	data_chunks = [data[i:i+4] for i in range(0, len(data), 4)]
	cipher = b''
	for i, data_chunk in enumerate(data_chunks):
		val = mersenne_twister_rng(seed, config, i)
		key_bytes = val.to_bytes(4, byteorder='big')
		cipher += bytes([k ^ d for k, d in zip(key_bytes, data_chunk)])

	return cipher