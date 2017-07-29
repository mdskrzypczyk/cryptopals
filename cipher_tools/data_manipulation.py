from base64 import b64encode, b64decode
from string import ascii_lowercase, ascii_uppercase

def left_rotate(num, bit_size, amount):
	num = num & int('1'*bit_size, 2)
	amount = amount % bit_size
	upper_bits = num & int('1'*amount + '0'*(bit_size - amount), 2)
	ret = ((num << amount) | (upper_bits >> (bit_size - amount))) & int('1'*bit_size, 2)
	return ret

def right_rotate(num, bit_size, amount):
	num = num & int('1'*bit_size, 2)
	amount = amount % bit_size
	lower_bits = num & int('1'*amount, 2)
	return (num >> amount) & (lower_bits << (bit_size - amount)) & int('1'*bit_size, 2)

def hex2b64(hex_string):
	byte_stream = bytes([int(hex_string[i:i+2],16) for i in range(0,len(hex_string),2)])
	return b64encode(byte_stream)

def b642hex(b64_string):
	hex_string = ''.join(["{0:02x}".format(b) for b in b64decode(b64_string)])
	return hex_string

def xor_hex_strings(hex1, hex2):
	result = ''.join(["{0:0x}".format(int(h1,16) ^ int(h2,16)) for h1,h2 in zip(hex1,hex2)])
	return result

def breakup_data(data, size):
	broken = [data[i:i+size] for i in range(0,len(data),size)]
	return broken

def transpose_blocks(blocks):
	t_blocks = [bytes()]*len(blocks[0])
	for block in blocks:
		for index in range(len(block)):
			t_blocks[index] += bytes([block[index]])
	return t_blocks

def ascii_to_hex(ascii):
	result = ''.join(["{0:02x}".format(a) for a in ascii])
	return result

def xor_with_single_byte(data, byte):
    return [d ^ byte for d in data]

def single_byte_xor_map(data):
    xor_data = {}
    ascii = ascii_uppercase + ascii_lowercase
    data = [ord(a) for a in ascii]
    for c in range(256):
        c_string = "{0:02x}".format(c) * int(len(target_string) / 2)
        x_string = xor_hex_strings(target_string, c_string)
        a_string = ''.join([chr(int(x_string[i:i+2],16)) for i in range(0, len(x_string),2)])
        xor_data[a_string] = chr(c)
    return xor_data

def repeated_key_xor(target_string, key_segment):
	key = key_segment*(int(len(target_string)/len(key_segment)) + 1)
	key = key[0:len(target_string)]
	hex_key = ''.join(["{0:02x}".format(ord(c)) for c in key])
	hex_string = ''.join(["{0:02x}".format(c) for c in target_string])
	return xor_hex_strings(hex_string,hex_key)