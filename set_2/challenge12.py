from challenge10 import *
from challenge11 import *
from base64 import b64decode

key = gen_random_count(16)
app = b64decode(open('12.txt').read())

def mod_encryption_oracle(data):
	data += app
	iv = bytes([0]*16)
	return encrypt_ecb(iv, key, data)

def discover_block_size(enc_func):
	data = b'\x00'
	enc_data = enc_func(b'')
	orig_len = len(enc_data)
	while orig_len == len(enc_func(data)):
		data += b'\x00'
	base_len = len(enc_func(data))
	while base_len == len(enc_func(data)):
		data += b'\x00'
	return len(enc_func(data)) - base_len

def discover_length_unknown(enc_func):
	data = b'\x00'
	enc_data = enc_func(b'')
	orig_len = len(enc_data)
	while orig_len == len(enc_func(data)):
		data += b'\x00'
	return orig_len - len(data)

def get_byte(enc_func, prefix, known, block_size, block_num):
	block_byte = {}
	for byte in range(256):
		byte = bytes([byte])
		block = breakup_cipher(enc_func((prefix + known)[-16:] + byte), block_size)[0]
		block_byte[block] = byte
	enc_short = breakup_cipher(enc_func(prefix), block_size)[block_num]
	return block_byte[enc_short]

def get_unknown(enc_func, enc_mode, block_size, len_unknown):
	known = b''
	num_blocks = int(len(enc_func(b''))/block_size)
	prefix = b'\x00' * block_size
	for block_num in range(num_blocks):
		known_block = b''
		
		for byte_num in range(1, block_size+1):
			byte = get_byte(enc_func, prefix[byte_num:], known_block, block_size, block_num)
			known_block += byte
			known += byte
			if len(known) == len_unknown:
				return known

		prefix = known_block

	return known

def discover_unknown(enc_func):
	block_size = discover_block_size(enc_func)
	enc_mode = detect_encryption(enc_func)
	len_unknown = discover_length_unknown(enc_func)
	unknown = get_unknown(enc_func, enc_mode, block_size, len_unknown)
	return unknown