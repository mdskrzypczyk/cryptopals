import struct
from cipher_tools.data_manipulation import breakup_data

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

def sha1pad(message):
	ml = len(message) * 8
	message += b'\x80' + b'\x00' * (-(len(message) + 9) % 64) + ml.to_bytes(8, 'big')
	return message

def sha1pad_verify(message):
	ml = struct.unpack(">Q", message[-8:])[0]
	num_bytes = int(ml/8)
	pad_len = -num_bytes % 64
	return message[-pad_len:] == b"\x80" + b"\x00"*(pad_len-9) + message[-8:]