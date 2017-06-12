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




	len_unknown = discover_length_unknown(mod2_encryption_oracle) - len_random
	len_prepad = (block_size - len_random) % block_size
	unknown = get_unknown_from_block_index(mod2_encryption_oracle, enc_mode, block_size, len_unknown, len_prepad, controlled_block_index)
	return unknown

print(discover_unknown_random_pre())