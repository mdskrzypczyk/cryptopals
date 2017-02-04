from base64 import b64encode,b64decode

def hex2b64(hex_string):
	byte_stream = bytes([int(hex_string[i:i+2],16) for i in range(0,len(hex_string),2)])
	return b64encode(byte_stream)

def b642hex(b64_string):
	return b64decode(b64_string)

#print(b642hex(hex2b64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))