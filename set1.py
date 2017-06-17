from cipher_tools.data_manipulation import hex2b64
def challenge1(hex_string):
	return hex2b64(hex_string)


from cipher_tools.data_manipulation import xor_hex_strings
def challenge2(hex1, hex2):
	return xor_hex_strings(hex1, hex2)


from cipher_tools.cracking import crack_one_char_xor
def challenge3(hex_cipher):
	return crack_one_char_xor(hex_cipher)


from cipher_tools.cracking import identify_one_char_xor
def challenge4(string_set):
	with open('challenge_data/4.txt') as f:
		string_set = f.read().splitlines()
	return identify_one_char_xor(string_set)


from cipher_tools.data_manipulation import repeated_key_xor
def challenge5():
	string_data = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	return repeated_key_xor(string_data, key)

from base64 import *
from cipher_tools.cracking import crack_repeated_key_xor
def challenge6():
	with open('challenge_data/6.txt') as f:
		data = str(b64decode(f.read()), 'utf-8')
	return crack_repeated_key_xor(data)


from cipher_tools.decryption import decrypt_ecb
def challenge7():
	iv = bytes(16)
	key = "YELLOW SUBMARINE"
	with open('challenge_data/7.txt') as f:
		data = b64decode(f.read())
	return decrypt_ecb(iv, key, data, pad=True)


from cipher_tools.cracking import identify_ecb_encrypted_data
def challenge8():
	with open('challenge_data/8.txt') as f:
		data = [b64decode(line) for line in f.read().splitlines()]
	return identify_ecb_encrypted_data(data)