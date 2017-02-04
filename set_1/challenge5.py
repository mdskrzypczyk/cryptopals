from challenge2 import xor_hex_strings

def repeated_key_xor(target_string, key_segment):
	key = key_segment*(int(len(target_string)/len(key_segment)) + 1)
	key = key[0:len(target_string)]
	hex_key = ''.join(["{0:02x}".format(ord(c)) for c in key])
	hex_string = ''.join(["{0:02x}".format(ord(c)) for c in target_string])
	return xor_hex_strings(hex_string,hex_key)

#print(repeated_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE"))