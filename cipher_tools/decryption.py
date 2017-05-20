from Crypto.Cipher import AES
from cipher_tools.padding import remove_pkcs7pad

def single_byte_ascii_decryptions(target_string):
    decrypted = single_byte_xor_map(target_string)
    ascii_decryptions = {}
    for d in decrypted.keys():
        ascii = [c for c in d if len(c) == len(c.encode())]
        if len(ascii) == len(d):
            ascii_decryptions[d] = decrypted[d]

    return ascii_decryptions

def decrypt_ecb(iv, key, data):
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), aes.decrypt(data))])
	data = remove_pkcs7pad(data)
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