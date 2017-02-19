from random import randint
from challenge10 import *
from challenge12 import *

key = gen_random_count(16)
rand = gen_random_count(randint(0,31))
app = b64decode(open('12.txt').read())

def mod2_encryption_oracle(data):
	data = rand + data + app
	iv = bytes([0]*16)
	return encrypt_ecb(iv, key, data)


def find_repeat_cipherblock(cipher, block_size):
	cipher_blocks = breakup_cipher(cipher, block_size)
	for i in range(len(cipher_blocks)-1):
		if cipher_blocks[i] == cipher_blocks[i+1]:
			return i

	return -1

def discover_len_random(enc_func, block_size):
	data = b'\x00' * (2*block_size)
	base_block_index = find_repeat_cipherblock(enc_func(data), block_size)
	while base_block_index == -1:
		data += b'\x00'
		base_block_index = find_repeat_cipherblock(enc_func(data), block_size)

	return base_block_index*block_size - len(data) % block_size

def get_byte(enc_func, prefix, known, block_size, block_num, len_prepad, base_block_index):
	block_byte = {}
	prepad = b'\x00'*len_prepad
	for byte in range(256):
		byte = bytes([byte])
		block = breakup_cipher(enc_func(prepad + (prefix + known)[-16:] + byte), block_size)[base_block_index]
		block_byte[block] = byte
	enc_short = breakup_cipher(enc_func(prepad + prefix), block_size)[block_num]
	return block_byte[enc_short]


def get_unknown_from_block_index(enc_func, enc_mode, block_size, len_unknown, len_prepad, block_index):
	known = b''
	num_blocks = int(len(enc_func(b''))/block_size)
	prefix = b'\x00' * block_size
	base_block_index = block_index
	for block_num in range(block_index, num_blocks):
		known_block = b''
		
		for byte_num in range(1, block_size+1):
			byte = get_byte(enc_func, prefix[byte_num:], known_block, block_size, block_num, len_prepad, base_block_index)
			known_block += byte
			known += byte
			if len(known) == len_unknown:
				return known

		prefix = known_block

	return known


def discover_unknown_random_pre():
	block_size = discover_block_size(mod2_encryption_oracle)
	enc_mode = detect_encryption(mod2_encryption_oracle)
	len_random = discover_len_random(mod2_encryption_oracle, block_size)
	controlled_block_index = int(len(pkcs7pad(b'\x00'*len_random, block_size)) / block_size)
	len_unknown = discover_length_unknown(mod2_encryption_oracle) - len_random
	len_prepad = (block_size - len_random) % block_size
	unknown = get_unknown_from_block_index(mod2_encryption_oracle, enc_mode, block_size, len_unknown, len_prepad, controlled_block_index)
	return unknown

print(discover_unknown_random_pre())