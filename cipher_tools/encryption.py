from Crypto.Cipher import AES
from cipher_tools.data_manipulation import breakup_data
def encrypt_ecb(iv, key, data):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), data)])
	return aes.encrypt(data)


def encrypt_cbc(iv, key, data):
	data_blocks = breakup_data(data, 16)
	cipher = bytes('', 'utf-8')
	for b in data_blocks:
		enc_b = encrypt_ecb(iv, key, b)
		cipher += enc_b
		iv = enc_b

	return cipher