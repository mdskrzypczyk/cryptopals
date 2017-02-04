from challenge3 import *

potential_ciphertexts = open('4.txt').read().splitlines()
potential_decryptions = []
for pc in potential_ciphertexts:
    d = decrypt_one_char_xor(pc)
    if d:
    	potential_decryptions.append(d)

#print(sorted(potential_decryptions, key=lambda x: getChi2(x[0]))[0])
