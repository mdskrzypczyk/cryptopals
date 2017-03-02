from cipher_tools.mathlib import *

def identify_one_char_xor(ciphers):
	potential_decryptions = []
	for pc in potential_ciphertexts:
    	d = decrypt_one_char_xor(pc)
    	if d:
    		potential_decryptions.append(d)
    return sorted(potential_decryptions, key=lambda x: getChi2(x[0]))[0]
    
def 

