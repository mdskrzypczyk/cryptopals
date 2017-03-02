from cipher_tools.data_manipulation import hex2b64

def challenge1(hex_string):
	return hex2b64(hex_string)

from cipher_tools.data_manipulation import xor_hex_strings

def challenge2(hex1, hex2):
	return xor_hex_strings(hex1, hex2)

def challenge3