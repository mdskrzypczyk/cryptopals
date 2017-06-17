def check_padding(iv_cipher):
	decrypted = decrypt_cbc(iv_cipher[0], key, iv_cipher[1])
	return pkcs7pad_verify(decrypted, 16)

def get_pad_len(pre_block, target_block):
	pad_poke = b'\x01' + bytes(len(pre_block)-1)
	modded_pre_block = [b1^b2 for b1,b2 in zip(pad_poke, pre_block)]
	pad_len = 16
	
	while check_padding((modded_pre_block, target_block)):
		pad_poke = (b'\x00' + pad_poke)[:len(pre_block)]
		modded_pre_block = [b1^b2 for b1,b2 in zip(pad_poke, pre_block)]
		pad_len -= 1

	return pad_len

def attack_valid_pad_block(pre_block, target_block):
	pad_len = get_pad_len(pre_block, target_block)
	known = bytes([pad_len])*pad_len

	pad = b'\x00'*len(pre_block)
	for byte_num in range(pad_len+1,17):
		known_mod = (pad + known)[-len(pre_block):]
		xor_mod = (pad + bytes([byte_num])*byte_num)[-len(pre_block):]
		
		curr_pre_blk = bytes([b1^b2^b3 for b1,b2,b3 in zip(pre_block, known_mod, xor_mod)])
		for byte in range(256):
			byte_mod = (pad + bytes([byte]) + bytes(byte_num-1))[-len(pre_block):]
			crafted_pre_blk = bytes([b1^b2 for b1,b2 in zip(curr_pre_blk, byte_mod)])

			if check_padding((crafted_pre_blk, target_block)):
				known = bytes([byte]) + known
				

	return known 

def attack_cbc_oracle_block(pre_block, target_block):
	pad = b'\x00'*len(pre_block)
	known = b''
	if check_padding((pre_block, target_block)):
		return attack_valid_pad_block(pre_block, target_block)

	for byte_num in range(1,17):
		known_mod = (pad + known)[-len(pre_block):]
		xor_mod = (pad + bytes([byte_num])*byte_num)[-len(pre_block):]
		
		curr_pre_blk = bytes([b1^b2^b3 for b1,b2,b3 in zip(pre_block, known_mod, xor_mod)])
		for byte in range(256):
			byte_mod = (pad + bytes([byte]) + bytes(byte_num-1))[-len(pre_block):]
			
			crafted_pre_blk = bytes([b1^b2 for b1,b2 in zip(curr_pre_blk, byte_mod)])

			if check_padding((crafted_pre_blk, target_block)):
				known = bytes([byte]) + known
				

	return known

def attack_cbc_oracle():
	iv, cipher = get_cipher_and_iv()
	blocks = [iv] + breakup_cipher(cipher, 16)
	known = b''
	for i in range(len(blocks)-1):
		pre = blocks[i]
		t_blk = blocks[i+1]
		r_blk = attack_cbc_oracle_block(pre, t_blk)
		known += r_blk

	pad_len = known[-1]
	return known[:-pad_len]

#print(attack_cbc_oracle(), chosen_str)
