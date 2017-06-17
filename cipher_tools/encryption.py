from Crypto.Cipher import AES
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