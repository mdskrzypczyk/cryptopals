def pkcs7pad(data, padded_modulo):
	len_pad = padded_modulo - (len(data) % padded_modulo)
	padding = bytes([len_pad]*len_pad)
	return data + padding

def remove_pkcs7pad(data):
	len_pad = list(data)[-1]
	return data[:-len_pad]

def pkcs7pad_verify(data, block_size):
	if len(data) % block_size != 0:
		return False

	pad_len = data[-1]

	if pad_len > block_size:
		return False

	pad = bytes(chr(pad_len)*pad_len, 'utf-8')
	return data[-pad_len:] == pad


	