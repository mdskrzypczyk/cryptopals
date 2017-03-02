from base64 import b64encode, b64decode

def hex2b64(hex_string):
	byte_stream = bytes([int(hex_string[i:i+2],16) for i in range(0,len(hex_string),2)])
	return b64encode(byte_stream)

def b642hex(b64_string):
	hex_string = ''.join(["{0:02x}".format(b) for b in b64decode(b64_string)])
	return hex_string

def xor_hex_strings(hex1, hex2):
	result = ''.join(["{0:0x}".format(int(h1,16) ^ int(h2,16)) for h1,h2 in zip(hex1,hex2)])
	return result

def breakup_cipher(cipher, size):
	broken = [cipher[i:i+size] for i in range(0,len(cipher),size)]
	return broken

def ascii_to_hex(ascii):
	result = ''.join(["{0:02x}".format(a) for a in ascii])
	return result

def xor_with_single_byte(data, byte):
    return [d ^ byte for d in data]

def repeated_key_xor(target_string, key_segment):
	key = key_segment*(int(len(target_string)/len(key_segment)) + 1)
	key = key[0:len(target_string)]
	hex_key = ''.join(["{0:02x}".format(ord(c)) for c in key])
	hex_string = ''.join(["{0:02x}".format(ord(c)) for c in target_string])
	return xor_hex_strings(hex_string,hex_key)