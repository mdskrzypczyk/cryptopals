from challenge17 import *
from base64 import b64decode

def gen_key_stream(key, data):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	return aes.encrypt(data)


def encrypt_ctr(nonce, key, data):
	data_blocks = breakup_cipher(data, 16)

	cipher = b''
	counter = int.from_bytes(nonce, 'big')
	for block in data_blocks:
		key_stream = gen_key_stream(key, nonce)
		enc_b = bytes([k^d for k,d in zip(key_stream, block)])
		cipher += enc_b

		counter += 72057594037927936
		nonce = counter.to_bytes(16, 'big')

	return cipher

def decrypt_ctr(nonce, key, cipher):
	cipher_blocks = breakup_cipher(cipher, 16)

	data = b''
	counter = int.from_bytes(nonce, 'big')
	for block in cipher_blocks:
		key_stream = gen_key_stream(key, nonce)
		dec_b = bytes([k^d for k,d in zip(key_stream, block)])
		data += dec_b

		counter += 72057594037927936
		nonce = counter.to_bytes(16, 'big')

	assert len(cipher) == len(data)
	return data

#nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
#key = bytes("YELLOW SUBMARINE", 'utf-8')
#data = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
#print(decrypt_ctr(nonce, key, data))