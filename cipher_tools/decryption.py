from Crypto.Cipher import AES
from cipher_tools.padding import remove_pkcs7pad
from cipher_tools.data_manipulation import breakup_data

def single_byte_ascii_decryptions(target_string):
    decrypted = single_byte_xor_map(target_string)
    ascii_decryptions = {}
    for d in decrypted.keys():
        ascii = [c for c in d if len(c) == len(c.encode())]
        if len(ascii) == len(d):
            ascii_decryptions[d] = decrypted[d]

    return ascii_decryptions

def decrypt_ecb(iv, key, data, pad):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), aes.decrypt(data))])
	if pad:
		data = remove_pkcs7pad(data)
	return data

def decrypt_cbc(iv, key, cipher, pad):
	cipher_blocks = breakup_data(cipher, 16)
	data = bytes([])
	for c in cipher_blocks:
		dec_c = decrypt_ecb(iv, key, c, pad=False)
		data += dec_c
		iv = c

	if pad:
		data = remove_pkcs7pad(data)
	return data