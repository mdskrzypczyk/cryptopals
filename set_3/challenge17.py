from Crypto.Cipher import AES
from base64 import b64decode
from random import randint

def pkcs7pad(data, padded_modulo):
	len_pad = padded_modulo - (len(data) % padded_modulo)
	padding = bytes([len_pad]*len_pad)
	return data + padding

def pkcs7pad_verify(data, block_size):
	if len(data) % block_size != 0:
		return False

	pad_len = data[-1]
	if pad_len > block_size or pad_len == 0:
		return False

	pad = bytes([pad_len])*pad_len
	return data[-pad_len:] == pad
				  
def decrypt_ecb(iv, key, data):
	print(iv, key, data)
	print(len(data))
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), aes.decrypt(data))])
	return data

def encrypt_ecb(iv, key, data):
	print(iv, key, data)
	print(len(data))
	aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
	data = bytes([a ^ b for a,b in zip(iv*int(len(data)/16), data)])
	return aes.encrypt(data)

def xor_hex_strings(hex1, hex2):
	result = ''.join(["{0:02x}".format(int(h1,16) ^ int(h2,16)) for h1,h2 in zip(hex1,hex2)])
	return result

def breakup_cipher(cipher, size):
	broken = [cipher[i:i+size] for i in range(0,len(cipher),size)]
	assert sum([len(b) for b in broken]) == len(cipher)
	return broken

def encrypt_cbc(iv, key, data):
	data_blocks = breakup_cipher(data, 16)
	cipher = bytes('', 'utf-8')
	for b in data_blocks:
		enc_b = encrypt_ecb(iv, key, b)
		cipher += enc_b
		iv = enc_b

	return cipher

def decrypt_cbc(iv, key, cipher):
	cipher_blocks = breakup_cipher(cipher, 16)
	data = bytes([])
	for c in cipher_blocks:
		dec_c = decrypt_ecb(iv, key, c)
		data += dec_c
		iv = c

	return data

def ascii_to_hex(ascii):
	result = ''.join(["{0:02x}".format(a) for a in ascii])
	return result

string_choices = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
				  'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
				  'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
				  'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
				  'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
				  'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
				  'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
				  'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
				  'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
				  'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

iv = bytes([randint(0, 15) for i in range(16)])
key = bytes([randint(0, 15) for i in range(16)])
chosen_str = bytes(string_choices[randint(0, len(string_choices) - 1)], 'utf-8')

def get_cipher_and_iv():
	padded_str = pkcs7pad(chosen_str, 16)
	return (iv, encrypt_cbc(iv, key, padded_str))

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
