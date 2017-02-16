from challenge3 import *

def find_one_char_xor_cipher(ciphers):
	potential_decryptions = []
	for pc in potential_ciphertexts:
    	d = decrypt_one_char_xor(pc)
    	if d:
    		potential_decryptions.append(d)
    return sorted(potential_decryptions, key=lambda x: getChi2(x[0]))[0]

potential_ciphertexts = open('4.txt').read().splitlines()
#print(find_one_char_xor_cipher(potential_ciphertexts))
