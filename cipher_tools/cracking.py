import binascii
from cipher_tools.mathlib import *
from cipher_tools.data_manipulation import *
from cipher_tools.decryption import *
    
def crack_one_char_xor(hex_string):
    candidate_keys = ["{0:02x}".format(i)*len(hex_string) for i in range(256)]
    hex_decryptions = [xor_hex_strings(hex_string, k) for k in candidate_keys]
    ascii_decryptions = [(''.join([chr(b) for b in binascii.unhexlify(hd)]), chr(i)) for hd,i in zip(hex_decryptions, range(256))]
    sorted_d = sorted(ascii_decryptions, key=lambda decryption : getChi2_english(decryption[0]))
    ranked_decryptions = list(filter(lambda decryption : getChi2_english(decryption[0]) != float('inf'), sorted_d))
    if ranked_decryptions:
        return ranked_decryptions[0]
    else:
        return None

def identify_one_char_xor(ciphers):
    potential_decryptions = []
    for pc in ciphers:
        best_decryption = crack_one_char_xor(pc)
        if best_decryption:
            potential_decryptions.append(best_decryption)
    return sorted(potential_decryptions, key=lambda decryption: getChi2_english(decryption))[0]

def find_repeated_key_xor_keysize(target):
    MAXKEYSIZE = 60
    NUMSMALLKEYS = 10
    size_score = {}
    for KEYSIZE in range(2, MAXKEYSIZE):
        dat1 = target[:KEYSIZE]
        dat2 = target[KEYSIZE:2*KEYSIZE]
        dist = hamming_distance(dat1, dat2)
        size_score[KEYSIZE] = dist / KEYSIZE

    sorted_sizes = sorted(size_score.items(), key=lambda x : x[1])
    return sorted_sizes[:NUMSMALLKEYS]

def crack_repeated_key_transposed_blocks(blocks):
    key = ''
    progress = [''] * len(blocks)
    for block in blocks:
        h_block = ascii_to_hex(block)
        assert len(h_block) == 2*len(block)
        d = crack_one_char_xor(h_block)
        if not d:
            return 'x'
        k = d[1]
        for index, d in zip(range(len(d[0])), d[0]):
            progress[index] += d
        
        key += k
    return key

def crack_repeated_key_xor(cipher):
    keysizes = find_repeated_key_xor_keysize(cipher)
    keys = []
    for size in keysizes:
        c_blocks = breakup_data(cipher, size[0])
        t_blocks = transpose_blocks(c_blocks)
        key = crack_repeated_key_transposed_blocks(t_blocks)
        keys.append(key)

    hex_decryptions = [repeated_key_xor(cipher, key) for key in keys]
    ascii_decryptions = [''.join([chr(int(h[i:i+2],16)) for i in range(0,len(h),2)]) for h in hex_decryptions]

    return sorted(ascii_decryptions, key=lambda x : getChi2_english(x))[0]

def identify_ecb_encrypted_data(dataset):
    reps = []
    for h in data:
        ascii = ''.join([chr(int(h[i:i+2], 16)) for i in range(0,len(h),2)])
        blocks = breakup_cipher(ascii, 16)
        rep = {}
        for block in blocks:
            if rep.get(block):
                rep[block] = rep[block]+1
            else:
                rep[block] = 1
        reps.append((rep,h))
    return sorted(reps, key = lambda x : max(x[0].values()))[-1][0]