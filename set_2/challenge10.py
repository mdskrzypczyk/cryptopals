from Crypto.Cipher import AES
from base64 import b64decode
from challenge9 import pkcs7pad
def decrypt_ecb(iv, key, data):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), aes.decrypt(data))])
	return data

def encrypt_ecb(iv, key, data):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), data)])
	return aes.encrypt(data)

def xor_hex_strings(hex1, hex2):
	result = ''.join(["{0:02x}".format(int(h1,16) ^ int(h2,16)) for h1,h2 in zip(hex1,hex2)])
	return result

def breakup_cipher(cipher, size):
	broken = [cipher[i:i+size] for i in range(0,len(cipher),size)]
	assert sum([len(b) for b in broken]) == len(cipher)
	return broken

def encrypt_cbc(iv, key, data):
	data_blocks = breakup_cipher(data, 16)
	cipher = bytes('', 'utf-8')
	for b in data_blocks:
		enc_b = encrypt_ecb(iv, key, b)
		cipher += enc_b
		iv = enc_b

	return cipher

def decrypt_cbc(iv, key, cipher):
	cipher_blocks = breakup_cipher(cipher, 16)
	data = bytes([])
	for c in cipher_blocks:
		dec_c = decrypt_ecb(iv, key, c)
		print(dec_c)
		data += dec_c
		iv = c

	pad_len = list(data)[-1]
	return data[:-pad_len]

def ascii_to_hex(ascii):
	result = ''.join(["{0:02x}".format(a) for a in ascii])
	return result

iv = bytes([0]*16)
key = "YELLOW SUBMARINE"
#data = b64decode(open('10.txt').read())
data = b'sdf'