from base64 import b64decode
from challenge3 import *
from challenge5 import repeated_key_xor
NUMSMALLKEYS = 20

def hamming_distance(string1, string2):
	distance = 0
	string1 += '\x00'*(len(string2) - len(string1))
	string2 += '\x00'*(len(string1) - len(string2))
	for c1, c2 in zip(string1, string2):
		xor = ord(c1) ^ ord(c2)
		bin_diff = bin(xor)
		distance += bin_diff.count('1')
	return distance

def find_keysize(target):
	MAXKEYSIZE = 60
	size_score = {}
	for KEYSIZE in range(2, MAXKEYSIZE):
		dat1 = target[:KEYSIZE]
		dat2 = target[KEYSIZE:2*KEYSIZE]
		dist = hamming_distance(dat1, dat2)
		size_score[KEYSIZE] = dist / KEYSIZE

	sorted_sizes = sorted(size_score.items(), key=lambda x : x[1])
	return sorted_sizes[:NUMSMALLKEYS]

def breakup_cipher(cipher, size):
	broken = [cipher[i:i+size] for i in range(0,len(cipher),size)]
	assert sum([len(b) for b in broken]) == len(cipher)
	return broken

def transpose_blocks(blocks):
	t_blocks = ['']*len(blocks[0])
	for block in blocks:
		for index in range(len(block)):
			t_blocks[index] += block[index]
	return t_blocks

def decrypt_blocks(blocks):
	key = ''
	progress = [''] * len(blocks)
	for block in blocks:
		h_block = ascii_to_hex(block)
		assert len(h_block) == 2*len(block)
		d = decrypt_one_char_xor(h_block)
		if not d:
			return 'x'
		k = d[1]
		for index, d in zip(range(len(d[0])), d[0]):
			progress[index] += d
		
		key += k
	return key

def decrypt_cipher(cipher):
	keysizes = find_keysize(cipher)
	keys = []
	for size in keysizes:
		c_blocks = breakup_cipher(cipher, size[0])
		
		t_blocks = transpose_blocks(c_blocks)
		
		key = decrypt_blocks(t_blocks)
		keys.append(key)
		pass

	return [repeated_key_xor(cipher, key) for key in keys]

def ascii_to_hex(ascii):
	result = ''.join(["{0:02x}".format(ord(a)) for a in ascii])
	return result

with open('6.txt') as f:
	data = str(b64decode(f.read()), 'utf-8')
	hex_d = decrypt_cipher(data)
	decrypted = []
	for h in hex_d:
		ascii = ''.join([chr(int(h[i:i+2],16)) for i in range(0,len(h),2)])
		decrypted.append(ascii)
		assert len(ascii) == len(data)
	#print(sorted(decrypted, key=lambda x : getChi2(x))[0])
