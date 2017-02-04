def xor_hex_strings(hex1, hex2):
	result = ''.join(["{0:0x}".format(int(h1,16) ^ int(h2,16)) for h1,h2 in zip(hex1,hex2)])
	return result

#print(xor_hex_strings("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965"))