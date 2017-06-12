import binascii
from random import randint
from cipher_tools.mathlib import *
from cipher_tools.data_manipulation import *
from cipher_tools.decryption import *
from cipher_tools.encryption import *
from cipher_tools.padding import *

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
    for candidate in dataset:
        ascii = ''.join([chr(c) for c in candidate])
        blocks = breakup_data(ascii, 16)
        rep = {}
        for block in blocks:
            if rep.get(block):
                rep[block] = rep[block]+1
            else:
                rep[block] = 1
        reps.append((rep,candidate))
    best_candidate = sorted(reps, key = lambda x : max(x[0].values()))[-1]
    return b64encode(best_candidate[1])

def identify_oracle_encryption(enc_func):
    test_data = bytes([0]*44)
    encrypted = enc_func(test_data)
    blocks = breakup_data(encrypted, 16)
    if len(set(blocks)) < len(blocks):
        return 'ecb'
    else:
        return 'cbc'

def get_block_size(enc_func):
    data = b'\x00'
    enc_data = enc_func(b'')
    orig_len = len(enc_data)
    while orig_len == len(enc_func(data)):
        data += b'\x00'
    base_len = len(enc_func(data))
    while base_len == len(enc_func(data)):
        data += b'\x00'
    return len(enc_func(data)) - base_len

def challenge12_get_length_appended_data(enc_func):
    data = b'\x00'
    enc_data = enc_func(b'')
    orig_len = len(enc_data)
    while orig_len == len(enc_func(data)):
        data += b'\x00'
    return orig_len - len(data)

def challenge12_get_byte(enc_func, prefix, known, block_size, block_num):
    block_byte = {}
    for byte in range(256):
        byte = bytes([byte])
        block = breakup_data(enc_func((prefix + known)[-16:] + byte), block_size)[0]
        block_byte[block] = byte
    enc_short = breakup_data(enc_func(prefix), block_size)[block_num]
    return block_byte[enc_short]

def challenge12_get_appended_data(enc_func, enc_mode, block_size, len_unknown):
    known = b''
    num_blocks = int(len(enc_func(b''))/block_size)
    prefix = b'\x00' * block_size
    for block_num in range(num_blocks):
        known_block = b''
        
        for byte_num in range(1, block_size+1):
            byte = challenge12_get_byte(enc_func, prefix[byte_num:], known_block, block_size, block_num)
            known_block += byte
            known += byte
            if len(known) == len_unknown:
                return known

        prefix = known_block

    return known

def crack_challenge12_oracle(enc_func):
    block_size = get_block_size(enc_func)
    enc_mode = identify_oracle_encryption(enc_func)
    len_unknown = challenge12_get_length_appended_data(enc_func)
    unknown = challenge12_get_appended_data(enc_func, enc_mode, block_size, len_unknown)
    return unknown

def profile_for(email, uid=10, role='user'):
    email = email.replace('&', '').replace('=', '')
    return '&'.join(['email='+email, 'uid='+str(uid), 'role='+role])

def encrypt_profile(iv, key, profile, enc_func):
    return enc_func(iv, key, profile)

def parse_profile(profile):
    profile_map = {}
    fields = str(profile, 'utf-8').split('&')
    for field in fields:
        key, value = tuple(field.split('='))
        if value.isdigit():
            profile_map[key] = int(value)
        else:
            profile_map[key] = value

    return profile_map

def decrypt_and_parse(iv, key, encrypted_profile, dec_func):
    return parse_profile(dec_func(iv, key, encrypted_profile))

def generate_encrypted_admin_user():
    iv = b'\x00'*16
    key = bytes([randint(0,255) for i in range(16)])
    admin_block_profile = profile_for('fo@bar.comadmin' + '\x0b'*11)
    role_offset_profile = profile_for('foo11@bar.com')
    encrypted_admin = breakup_data(encrypt_profile(iv, key, bytes(admin_block_profile, 'utf-8'), encrypt_ecb),16)[1]
    cprofile = breakup_data(encrypt_profile(iv, key, bytes(role_offset_profile, 'utf-8'), encrypt_ecb),16)
    chopped = cprofile[:len(cprofile)-1]
    encrypted_profile = b''.join(cprofile + [encrypted_admin])
    return {"Profile": encrypted_profile, "Key": key, "Decryption": decrypt_and_parse(iv, key, encrypted_profile, decrypt_ecb)}

def challenge14_repeat_cipherblock_index(cipher, block_size):
	cipher_blocks = breakup_data(cipher, block_size)
	for i in range(len(cipher_blocks)-1):
		if cipher_blocks[i] == cipher_blocks[i+1]:
			return i

	return -1

def challenge14_get_len_random(enc_func, block_size):
	data = b'\x00' * (2*block_size)
	base_block_index = challenge14_repeat_cipherblock_index(enc_func(data), block_size)
	while base_block_index == -1:
		data += b'\x00'
		base_block_index = challenge14_repeat_cipherblock_index(enc_func(data), block_size)

	return base_block_index*block_size - len(data) % block_size


def challenge14_get_byte(enc_func, prefix, known, block_size, block_num, len_prepad, base_block_index):
    block_byte = {}
    prepad = b'\x00' * len_prepad
    for byte in range(256):
        byte = bytes([byte])
        block = breakup_data(enc_func(prepad + (prefix + known)[-16:] + byte), block_size)[base_block_index]
        block_byte[block] = byte
    enc_short = breakup_data(enc_func(prepad + prefix), block_size)[block_num]
    return block_byte[enc_short]


def challenge14_get_unknown(enc_func, enc_mode, block_size, len_unknown, len_prepad, block_index):
    known = b''
    num_blocks = int(len(enc_func(b'')) / block_size)
    prefix = b'\x00' * block_size
    base_block_index = block_index
    for block_num in range(block_index, num_blocks):
        known_block = b''

        for byte_num in range(1, block_size + 1):
            byte = challenge14_get_byte(enc_func, prefix[byte_num:], known_block, block_size, block_num, len_prepad,
                            base_block_index)
            known_block += byte
            known += byte
            if len(known) == len_unknown:
                return known

        prefix = known_block

    return known

def crack_challenge14_oracle(oracle):
	block_size = get_block_size(oracle)
	enc_mode = identify_oracle_encryption(oracle)
	len_random = challenge14_get_len_random(oracle, block_size)
	controlled_block_index = int(len(pkcs7pad(b'\x00'*len_random, block_size)) / block_size)
	len_unknown = challenge12_get_length_appended_data(oracle) - len_random
	len_prepad = (block_size - len_random) % block_size
	unknown = challenge14_get_unknown(oracle, enc_mode, block_size, len_unknown, len_prepad, controlled_block_index)
	return unknown