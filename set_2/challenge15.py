def pkcs7pad_verify(data, block_size):
	if len(data) % block_size != 0:
		return False

	pad_len = ord(data[-1])
	print(pad_len)
	if pad_len > block_size:
		return False

	pad = chr(pad_len)*pad_len
	return data[-pad_len:] == pad

#valid = "ICE ICE BABY\x04\x04\x04\x04"
#invalid = "ICE ICE BABY\x05\x05\x05\x05"
#print(pkcs7pad_verify(valid,16))
#print(pkcs7pad_verify(invalid,16))