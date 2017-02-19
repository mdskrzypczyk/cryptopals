from urllib.parse import quote
from challenge11 import *
from challenge12 import *
from challenge15 import *

pre_data = quote("comment1=cooking%20MCs;userdata=", safe='%')
post_data = quote(";comment2=%20like%20a%20pound%20of%20bacon", safe='%')
iv = bytes([0]*16)
key = gen_random_count(16)

def enc_oracle(data):
	wrapped_data = pkcs7pad(bytes(pre_data + data + post_data, 'utf-8'), 16)
	return encrypt_cbc(iv, key, wrapped_data)

def dec_check_admin(cipher):
	print(cipher)
	data = decrypt_cbc(iv, key, cipher)
	print(data)

	return b';admin=true;' in data

def num_common_prefix_blocks(data1, data2):
	broken_data1 = breakup_cipher(data1, 16)
	broken_data2 = breakup_cipher(data2, 16)
	count = 0
	for b1, b2 in zip(broken_data1, broken_data2):
		if b1 == b2:
			count += 1
		else:
			return count

	return count

def detect_controlled_block():
	num_prefix_blocks = num_common_prefix_blocks(enc_oracle(''), enc_oracle('\x00'))
	return num_prefix_blocks

def find_prepad(controlled_index):
	if controlled_index == 0:
		return 0
	data = ''
	while breakup_cipher(enc_oracle(data),16)[controlled_index] != breakup_cipher(enc_oracle(data+'\x00'),16)[controlled_index]:
		data += 'a'
	return data + 'a'*16

def produce_admin_decryption():
	blk_index = detect_controlled_block()
	prepad = find_prepad(blk_index)
	data = prepad + chr(ord(';') ^ 1) + 'admin=true' + chr(ord(';') ^ 1) + '\x00'*4
	cipher = enc_oracle(data)
	c_blocks = breakup_cipher(cipher,16)
	modded_block = list(c_blocks[blk_index+1])
	modded_block[0] ^= 0x01
	modded_block[11] ^=  0x01
	new_cipher = b''.join(c_blocks[:blk_index+1] + [bytes(modded_block)] + c_blocks[-len(c_blocks) + blk_index+2:])
	recovered = dec_check_admin(new_cipher)
	return recovered

#print(produce_admin_decryption())
