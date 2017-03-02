from Crypto.Cipher import AES

def decrypt_ecb(iv, key, data):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), aes.decrypt(data))])
	return data


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