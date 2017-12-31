import binascii
import operator
import time
import struct
import requests
import base64
from math import ceil
from pyasn1.codec.ber import encoder as ber_encoder
from pyasn1.type import univ
from random import randint
from collections import defaultdict
from itertools import combinations
from asn.pkcs_15_signature import *
from cipher_tools.dsa import *
from cipher_tools.mathlib import *
from cipher_tools.data_manipulation import *
from cipher_tools.decryption import *
from cipher_tools.encryption import *
from cipher_tools.hashing import *
from cipher_tools.padding import *
from cipher_tools.protocols import *
from cipher_tools.rng import *

def crack_one_char_xor(hex_string):
    candidate_keys = ["{0:02x}".format(i)*(int(len(hex_string)/2)) for i in range(256)]
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
    progress = [''] * len(blocks[0])
    for block in blocks:
        h_block = ascii_to_hex(block)
        d = crack_one_char_xor(h_block)
        if not d:
            return 'x'
        k = d[1]
        for index, de in zip(range(len(d[0])), d[0]):
            progress[index] += de
        
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
    return enc_func(iv, key, profile, pad=False)

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
    return parse_profile(dec_func(iv, key, encrypted_profile, pad=True))

def generate_encrypted_admin_user():
    iv = b'\x00'*16
    key = bytes([randint(0,255) for i in range(16)])
    admin_block_profile = profile_for('fo@bar.comadmin' + '\x0b'*11)
    role_offset_profile = profile_for('foo11@bar.com')
    encrypted_admin = breakup_data(encrypt_profile(iv, key, bytes(admin_block_profile, 'utf-8'), encrypt_ecb),16)[1]
    cprofile = breakup_data(encrypt_profile(iv, key, bytes(role_offset_profile, 'utf-8'), encrypt_ecb),16)
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

def num_common_prefix_blocks(data1, data2):
    broken_data1 = breakup_data(data1, 16)
    broken_data2 = breakup_data(data2, 16)
    count = 0
    for b1, b2 in zip(broken_data1, broken_data2):
        if b1 == b2:
            count += 1
        else:
            return count

    return count

def challenge16_detect_controlled_block(oracle):
    num_prefix_blocks = num_common_prefix_blocks(oracle(''), oracle('\x00'))
    return num_prefix_blocks

def challenge16_find_prepad(oracle, controlled_index):
    if controlled_index == 0:
        return 0
    data = ''
    while breakup_data(oracle(data),16)[controlled_index] != breakup_data(oracle(data+'\x00'),16)[controlled_index]:
        data += 'a'
    return data + 'a'*16

def crack_challenge16_oracle(oracle, verifier):
    blk_index = challenge16_detect_controlled_block(oracle)
    prepad = challenge16_find_prepad(oracle, blk_index)
    data = prepad + chr(ord(';') ^ 1) + 'admin=true' + chr(ord(';') ^ 1) + '\x00'*4
    cipher = oracle(data)
    c_blocks = breakup_data(cipher,16)
    modded_block = list(c_blocks[blk_index+1])
    modded_block[0] ^= 0x01
    modded_block[11] ^=  0x01
    new_cipher = b''.join(c_blocks[:blk_index+1] + [bytes(modded_block)] + c_blocks[-len(c_blocks) + blk_index+2:])
    if verifier(new_cipher):
        return new_cipher
    else:
        print("Failed")
        return


def challenge17_get_pad_len(oracle, pre_block, target_block):
    pad_poke = b'\x01' + bytes(len(pre_block) - 1)
    modded_pre_block = [b1 ^ b2 for b1, b2 in zip(pad_poke, pre_block)]
    pad_len = 16

    while oracle((modded_pre_block, target_block)):
        pad_poke = (b'\x00' + pad_poke)[:len(pre_block)]
        modded_pre_block = [b1 ^ b2 for b1, b2 in zip(pad_poke, pre_block)]
        pad_len -= 1

    return pad_len


def challenge17_crack_valid_pad_block(oracle, pre_block, target_block):
    pad_len = challenge17_get_pad_len(oracle, pre_block, target_block)
    known = bytes([pad_len]) * pad_len

    pad = b'\x00' * len(pre_block)
    for byte_num in range(pad_len + 1, 17):
        known_mod = (pad + known)[-len(pre_block):]
        xor_mod = (pad + bytes([byte_num]) * byte_num)[-len(pre_block):]

        curr_pre_blk = bytes([b1 ^ b2 ^ b3 for b1, b2, b3 in zip(pre_block, known_mod, xor_mod)])
        for byte in range(256):
            byte_mod = (pad + bytes([byte]) + bytes(byte_num - 1))[-len(pre_block):]
            crafted_pre_blk = bytes([b1 ^ b2 for b1, b2 in zip(curr_pre_blk, byte_mod)])

            if oracle((crafted_pre_blk, target_block)):
                known = bytes([byte]) + known

    return known


def challenge17_crack_oracle_block(oracle, pre_block, target_block):
    pad = b'\x00' * len(pre_block)
    known = b''
    if oracle((pre_block, target_block)):
        return challenge17_crack_valid_pad_block(oracle, pre_block, target_block)

    for byte_num in range(1, 17):
        known_mod = (pad + known)[-len(pre_block):]
        xor_mod = (pad + bytes([byte_num]) * byte_num)[-len(pre_block):]

        curr_pre_blk = bytes([b1 ^ b2 ^ b3 for b1, b2, b3 in zip(pre_block, known_mod, xor_mod)])
        for byte in range(256):
            byte_mod = (pad + bytes([byte]) + bytes(byte_num - 1))[-len(pre_block):]

            crafted_pre_blk = bytes([b1 ^ b2 for b1, b2 in zip(curr_pre_blk, byte_mod)])

            if oracle((crafted_pre_blk, target_block)):
                known = bytes([byte]) + known

    return known


def crack_challenge17_oracle(oracle, iv, cipher):
    blocks = [iv] + breakup_data(cipher, len(iv))
    known = b''
    for i in range(len(blocks) - 1):
        pre = blocks[i]
        t_blk = blocks[i + 1]
        r_blk = challenge17_crack_oracle_block(oracle, pre, t_blk)
        known += r_blk

    return remove_pkcs7pad(known)


def recover_common_nonce_ctr_key_pairs(cipher1, cipher2):
    pos = 0
    index_key_pairs = {}
    for c1, c2 in zip(cipher1, cipher2):
        p = bytes([c1 ^ c2])
        if p.isupper() or p.islower():
            index_key_pairs[pos] = (c1 ^ 32, c2 ^ 32)
        pos += 1
    return index_key_pairs


def crack_common_nonce_ctr_key_via_spaces(cipherset):
    recovered_key_dict = {}
    for cipher1 in cipherset:
        for cipher2 in cipherset - set([cipher1]):
            recovered_pairs = recover_common_nonce_ctr_key_pairs(cipher1, cipher2)
            for index, k in recovered_pairs.items():
                k1, k2 = k
                if index not in recovered_key_dict.keys():
                    recovered_key_dict[index] = {k1: 1, k2: 1}

                else:
                    index_key_dict = recovered_key_dict[index]
                    k1_count = index_key_dict.get(k1, 0)
                    index_key_dict[k1] = k1_count + 1
                    k2_count = index_key_dict.get(k2, 0)
                    index_key_dict[k2] = k2_count + 1

                    recovered_key_dict[index] = index_key_dict

    keystream_length = max([len(cipher) for cipher in cipherset])
    recovered_key = []
    for index in range(keystream_length):

        if index in recovered_key_dict.keys():
            index_key_dict = recovered_key_dict[index]
            keystream_byte = max(index_key_dict.items(), key=operator.itemgetter(1))[0]
            recovered_key.append(keystream_byte)
        else:
            recovered_key.append(None)

    return recovered_key


def crack_common_nonce_ctr(cipherset):
    recovered_key = crack_common_nonce_ctr_key_via_spaces(set(cipherset))
    cipher = list(cipherset)[37]
    decrypted = []
    recovered_key[0] = cipherset[0][0] ^ ord('I')
    recovered_key[30] = cipherset[27][30] ^ ord('e')
    recovered_key[31] = cipherset[27][31] ^ ord('n')
    recovered_key[33] = cipherset[37][33] ^ ord('t')
    recovered_key[34] = cipherset[37][34] ^ ord('u')
    recovered_key[35] = cipherset[37][35] ^ ord('r')
    recovered_key[36] = cipherset[37][36] ^ ord('n')
    recovered_key[37] = cipherset[37][37] ^ ord(',')
    for c, k in zip(cipher, recovered_key):
        if k:
            decrypted.append(c ^ k)
        else:
            decrypted.append(0)

    return (bytes(decrypted), bytes(recovered_key))


def crack_common_nonce_ctr_via_stats(cipherset):
    common_length = min([len(c) for c in cipherset])
    cipher_segments = [c[:common_length] for c in cipherset]
    combined = b''.join(cipher_segments)
    recovered_cipher = list(bytes(crack_repeated_key_xor(combined), 'utf-8'))

    for i in range(0, len(recovered_cipher), common_length):
        recovered_cipher[i] ^= ord('5') ^ ord('F')
        recovered_cipher[i+2] ^= ord(',') ^ ord('i')

    recovered_cipher = bytes(recovered_cipher)
    recovered_segments = breakup_data(recovered_cipher, common_length)

    index_longest = cipherset.index(max(cipherset, key=len))
    segment_remainder = b' please your eardrums; / I sit back and observe the whole scenery'
    key_remainder = bytes([r ^ c for r, c in zip(segment_remainder, cipherset[index_longest][common_length:])])

    for i, cipher in enumerate(cipherset):
        for k, c in zip(key_remainder, cipher[common_length:]):
            recovered_segments[i] += bytes([c ^ k])

    return recovered_segments


def crack_challenge22_oracle(oracle):
    start = int(time.time())
    val = oracle()
    stop = int(time.time())
    for i in range(start, stop):
        output = mersenne_twister_rng(i, MT19937_config, 0)
        if val == output:
            return i

    return None


def undo_temper_operation(fin_val, and_mask, shift_amount, length, dir):
    str_fin = format(fin_val, '032b')
    str_fin = ''.join(reversed(str_fin)) if dir == 'l' else str_fin
    str_and = format(and_mask, '032b')
    str_and = ''.join(reversed(str_and)) if dir == 'l' else str_and
    str_rec = str_fin[:shift_amount]

    for i in range(shift_amount, length):
        f, a, rs = str_fin[i], str_and[i], str_rec[i-shift_amount]
        str_rec += str((int(a) & int(rs)) ^ int(f))

    str_rec = ''.join(reversed(str_rec)) if dir == 'l' else str_rec
    return int(str_rec, 2)


def mersenne_twister_untemper(y, config):
    x = undo_temper_operation(y, int('1'*config['w'], 2), config['l'], config['w'], 'r')
    x = undo_temper_operation(x, config['c'], config['t'], config['w'], 'l')
    x = undo_temper_operation(x, config['b'], config['s'], config['w'], 'l')
    x = undo_temper_operation(x, config['d'], config['u'], config['w'], 'r')
    return x


def crack_challenge24_oracle(oracle):
    len_plain = 16
    known_byte = b'A'
    plaintext = known_byte*len_plain
    ciphertext = oracle(plaintext)

    num_extra_bytes = len(ciphertext) % 4
    if num_extra_bytes:
        ciphertext = ciphertext[:-num_extra_bytes]

    key_idx = int(len(ciphertext) / 4) - 3
    len_key_bytes = 12
    keyed_bytes = ciphertext[-len_key_bytes:]
    key_sequence = bytes([ord(known_byte) ^ kb for kb in keyed_bytes])
    for i in range(2**16 - 1):
        keystream = b''.join([mersenne_twister_rng(i, MT19937_config, r).to_bytes(4, byteorder='big') for r in range(key_idx, key_idx+3)])
        if keystream[-len(key_sequence):] == key_sequence:
            return i

    raise Exception("Key not found")

def crack_challenge25_oracle(oracle, edit):
    ciphertext = oracle()
    plaintext = edit(ciphertext, 0, ciphertext)
    return plaintext

def crack_challenge26_oracle(oracle):
    admin_string = b"1;admin=true"
    x_string = b"1\x00admin\x00true"
    x_admin = admin_string.replace(b';', b':').replace(b'=', b'<')
    cx_string = oracle(x_string)
    cx_admin = oracle(x_admin)
    crafted = [ca if ca == cx else ca ^ 1 for ca, cx in zip(cx_admin, cx_string)]
    return crafted

def crack_challenge27_oracle(oracle, verifier):
    counter = 0
    while True:
        data = counter.to_bytes(48, 'big')
        data = bytes([d & 0x7F for d in data])
        cipher = oracle(data)
        c_blocks = breakup_data(cipher, 16)
        crafted = c_blocks[0] + bytes(16) + c_blocks[0]
        try:
            verifier(crafted)
        except Exception as e:
            d_blocks = breakup_data(e.data, 16)
            return bytes([d1 ^ d2 for d1, d2 in zip(d_blocks[0], d_blocks[2])])
        counter += 1

def length_extend_sha1(sha, original_len, new_message):
    hh = [struct.unpack(">I", b)[0] for b in breakup_data(sha, 4)]
    total_len = original_len + len(new_message)*8
    return sha1(new_message, message_len=total_len, h0=hh[0], h1=hh[1], h2=hh[2], h3=hh[3], h4=hh[4])

def length_extend_md4(md, original_len, new_message):
    hh = [struct.unpack("<I", b)[0] for b in breakup_data(md, 4)]
    total_len = original_len + len(new_message) * 8
    return md4(new_message, message_len=total_len, h0=hh[0], h1=hh[1], h2=hh[2], h3=hh[3])

def crack_challenge31_oracle():
    host = 'http://127.0.0.1'
    port = 5000
    endpoint = 'challenge31/?file=set1.py&signature={}'
    signature= b''
    padding = b'\x00'*20
    for i in range(64):
        byte_time_dict = {}
        for byte in range(256):
            test_sig = (signature+byte.to_bytes(1, 'big')+padding)[:20]
            url = "{}:{}/{}".format(host, str(port), endpoint.format(str(binascii.hexlify(test_sig), 'utf-8')))

            start = time.time()
            response = requests.get(url)
            end = time.time()

            if response.status_code == 200:
                return test_sig

            elif response.status_code == 500:
                byte_time_dict[byte.to_bytes(1, 'big')] = end - start

        signature += sorted(byte_time_dict.items(), key=lambda x: x[1])[-1][0]
    return b""

class mitm_dh_wire:
    def __init__(self, dh_group=None):
        self.wire = {}
        self.mal_clients = {}
        self.dh_group = dh_group

    def __getitem__(self, item):
        return self.wire[item]

    def pop(self, item):
        return self.wire.pop(item)

    # Replace with whatever triggers the [] call of a map
    def __setitem__(self, dest, data):
        self.wire[dest] = data
        fields = data.keys()
        source = data["from"]
        if set(["p", "g", "pub"]) < set(fields):
            self._inject_params(source, dest, data)
        elif set(["p", "g"]) < set(fields):
            self._inject_dh_group(source, dest, data)
        elif "pub" in fields:
            self._inject_pub(source, dest, data)
        elif "msg" in fields:
            self._inject_msg(source, dest, data)
        else:
            self.wire[dest] = data

    def _inject_params(self, source, dest, data):
        self.mal_clients[dest] = DiffieHellmanClient(name=dest, wire=self.wire)
        self.mal_clients[source] = DiffieHellmanClient(name=source, wire=self.wire, p=dh_group['p'], g=dh_group['g'])
        self.mal_clients[dest]._recv_params()
        self.mal_clients[source]._generate_keypair()
        self.mal_clients[source]._send_params(dest)

    def _inject_pub(self, source, dest, data):
        self.mal_clients[dest]._recv_pub()
        self.mal_clients[source]._send_pub(dest)

    def _inject_msg(self, source, dest, data):
        msg = self.mal_clients[dest]._recv_msg()
        self.mal_clients[source]._send_msg(dest, msg)

    def _inject_dh_group(self, source, dest, data):
        self.mal_clients[dest] = DiffieHellmanClient(name=dest, wire=self.wire)
        self.mal_clients[source] = DiffieHellmanClient(name=source, wire=self.wire, p=self.dh_group['p'], g=self.dh_group['g'])
        self.mal_clients[dest]._recv_dh_group()
        self.mal_clients[source]._generate_keypair()
        self.mal_clients[source]._send_dh_group(dest)

def follow_lead(curr_sig=b'', timeout=0.0):
    if len(curr_sig) == 20:
        return None

    host = 'http://127.0.0.1'
    port = 5000
    endpoint = 'challenge32/?file=set1.py&signature={}'
    padding = b'\x00' * 20

    byte_time_dict = {}
    for byte in range(256):
        time.sleep(0.02)
        test_sig = (curr_sig + byte.to_bytes(1, 'big') + padding)[:20]
        url = "{}:{}/{}".format(host, str(port), endpoint.format(str(binascii.hexlify(test_sig), 'utf-8')))

        start = time.time()
        response = requests.get(url)
        end = time.time()

        if response.status_code == 200:
            return test_sig

        elif response.status_code == 500:
            byte_time_dict[byte.to_bytes(1, 'big')] = end - start

    sig_leads = [(curr_sig + b[0], b[1]) for b in sorted(byte_time_dict.items(), key=lambda x: -x[1])]
    if not sig_leads:
        return None

    avg_duration = sum([sl[1] for sl in sig_leads]) / len(sig_leads)
    if avg_duration < timeout + 0.002:
        return None

    for sig, timeout in sig_leads:
        res = follow_lead(sig, avg_duration)
        if res:
            return res

    return None


def crack_challenge31_oracle_reduced_delay():
    return follow_lead()


def crack_challenge40(rsa_ciphers, pub_keys):
    c0 = int.from_bytes(rsa_ciphers[0], 'big')
    c1 = int.from_bytes(rsa_ciphers[1], 'big')
    c2 = int.from_bytes(rsa_ciphers[2], 'big')
    n0 = pub_keys[0][1]
    n1 = pub_keys[1][1]
    n2 = pub_keys[2][1]
    m = three_residue_crt(c0, n0, c1, n1, c2, n2)
    return m.to_bytes(m.bit_length() // 8 + 1, 'big')


def crack_challenge41():
    # Get original cipher + public keys
    host = 'http://127.0.0.1'
    port = 5000
    endpoint = 'challenge41/get_message_and_pub'
    response = requests.get("{}:{}/{}".format(host, port, endpoint))
    cipher = base64.b64decode(response.json()['cipher'])
    pub = response.json()['keys']

    # Craft C'
    c = int.from_bytes(cipher, 'big')
    s = 2
    crafted = (modexp(s, pub[0], pub[1]) * c) % pub[1]
    crafted_cipher = crafted.to_bytes(crafted.bit_length() // 8 + 1, 'big')

    # Submit C' to be decrypted
    endpoint = 'challenge41/'
    response = requests.post("{}:{}/{}".format(host, port, endpoint), json={'cipher': str(base64.b64encode(crafted_cipher), 'utf-8')})

    # Multiply by S inverse to recover original plain
    crafted_plain = base64.b64decode(response.json()['data'])
    p = int.from_bytes(crafted_plain, 'big')
    plain = (p * modinv(s, pub[1])) % pub[1]

    return plain.to_bytes(plain.bit_length() // 8 + 1, 'big')

def crack_challenge42(message):
    digest = Digest(md4(message))

    digest_algorithm = DigestAlgorithmIdentifier()
    digest_algorithm.setComponentByName('algorithm', univ.ObjectIdentifier('1.2.840.113549.1.1.4'))

    digest_info = DigestInfo()
    digest_info.setComponentByName('digest', digest)
    digest_info.setComponentByName('digestAlgorithm', digest_algorithm)

    byte_digest_info = ber_encoder.encode(digest_info)
    plain = b'\x00\x01\xff\x00' + byte_digest_info
    garbage = b'\x00'*(128-len(plain))
    mal = plain + garbage
    mal_int = int.from_bytes(mal, 'big')
    pub_key = (3, int.from_bytes(b'\xff'*128, 'big'))

    root = find_cube_root(mal_int)
    if modexp(root, pub_key[0], pub_key[1]) != mal_int:
        hi = modexp(root+1, pub_key[0], pub_key[1])
        diff = hi - mal_int
        if diff > int.from_bytes(b'\xff'*len(garbage), 'big'):
            raise Exception("Broken")
        mal_sig = (root+1).to_bytes(128, 'big')
    else:
        mal_sig = lo.to_bytes(128, 'big')

    return (mal_sig, pub_key)

def crack_challenge43(message, signature, params):
    q = params['q']
    h = int.from_bytes(sha1(message), 'big')
    r,s = signature
    for k in range(2, 2**16):
        private_key = (modinv(r, q) * ((s * k) - h)) % q
        if dsa_calculate_signature(k, h, private_key, params) == signature:
            return private_key

def crack_challenge44(challenge_data, params):
    q = params['q']
    for msg_data1, msg_data2 in combinations(challenge_data, 2):
        m1, m2 = msg_data1['m'], msg_data2['m']
        s1, s2 = msg_data1['s'], msg_data2['s']
        r1, r2 = msg_data1['r'], msg_data2['r']
        m_diff, s_diff = (m1 - m2) % q, (s1 - s2) % q
        k = (modinv(s_diff, q) * m_diff) % q

        priv_key1 = (modinv(r1, q) * ((s1 * k) - m1)) % q
        priv_key2 = (modinv(r2, q) * ((s2 * k) - m2)) % q

        if k > 1 and priv_key1 == priv_key2:
            if dsa_calculate_signature(k, m1, priv_key1, params) == (r1, s1) and \
                dsa_calculate_signature(k, m2, priv_key1, params) == (r2, s2):
                return priv_key1

def generate_magic_signature(pub_key, params):
    z = 2
    p = params['p']
    q = params['q']
    r = ((pub_key ** z) % p) % q
    s = (modinv(z, q) * r) % q
    return (r, s)

def crack_challenge46(cipher, pub_key, oracle):
    e, n = pub_key
    lo, hi = 0, n - 1
    factor = 2
    while hi != lo + 1:
        cipher_int = int.from_bytes(cipher, 'big')
        cipher_double = (cipher_int) * modexp(factor, e, n) % n
        new_cipher = cipher_double.to_bytes((cipher_double.bit_length() // 8) + 1, 'big')

        if oracle(new_cipher):
            lo += (hi - lo) // 2
        else:
            hi -= (hi - lo) // 2

        factor *= 2

    for s in range(-256, 256):
        if modexp(hi+s, e, n) == cipher_int:
            return (hi+s).to_bytes(((hi+s).bit_length() // 8) + 1, 'big')

    raise Exception("Failed to decrypt")

def crack_challenge47_step1(c, e, n, oracle):
    s = 1
    c_0 = c * modexp(s, e, n)
    while not oracle(int_to_bytes(c_0)):
        s += 1
        c_0 = c * modexp(s, e, n)
    return s, c_0

def crack_challenge47_step2a(c_0, e, n, b, oracle):
    s = ceildiv(n, (3*b))
    c = c_0 * modexp(s, e, n)
    while not oracle(int_to_bytes(c)):
        s += 1
        c = c_0 * modexp(s, e, n)
    return s

def crack_challenge47_step2b(c_0, s, e, n, oracle):
    i = 1
    c = c_0 * modexp(s+i, e, n)
    while not oracle(int_to_bytes(c)):
        i += 1
        c = c_0 * modexp(s+i, e, n)
    return s+i

def crack_challenge47_step2c(c_0, e, n, b, lo, hi, s, oracle):
    r = ceildiv(2 * (hi * s - 2 * b), n)
    while True:
        lower = ceildiv(2*b + r*n, hi)
        upper = floordiv(3*b + r*n, lo) + 1
        for s_i in range(lower, upper):
            c = c_0*modexp(s_i, e, n)
            if oracle(int_to_bytes(c)):
                return s_i
        r += 1

def crack_challenge47_step3(m, s, n, b):
    m_i = []
    for lo, hi in m:
        lower = ceildiv(lo*s - 3*b + 1, n)
        upper = floordiv(hi*s - 2*b, n) + 1
        for r in range(lower, upper):
            new_lo = max(lo, ceildiv(2*b + r*n, s))
            new_hi = min(hi, floordiv(3*b - 1 + r*n, s))
            if new_lo <= new_hi:
                m_i.append((new_lo, new_hi))

    return m_i


def crack_challenge47(cipher, pub_key, oracle):
    cipher_int = int.from_bytes(cipher, 'big')
    e, n = pub_key
    k = ceil(n.bit_length() / 8)
    b = 2**(8*(k-2))

    # Step 1, blinding
    s_0, c_0 = crack_challenge47_step1(cipher_int, e, n, oracle)
    m = [[(2*b, (3*b)-1)]]

    i = 1
    s = [s_0]
    while True:
        if i == 1:
            s.append(crack_challenge47_step2a(c_0, e, n, b, oracle))

        elif len(m[i-1]) > 1 and i > 1:
            s.append(crack_challenge47_step2b(c_0, s[i-1], e, n, oracle))

        elif len(m[i-1]) == 1:
            lo, hi = m[i-1][0]
            s.append(crack_challenge47_step2c(c_0, e, n, b, lo, hi, s[i-1], oracle))

        m.append(crack_challenge47_step3(m[i-1], s[i], n, b))
        print(m)
        if len(m[i]) == 1 and m[i][0][0] == m[i][0][1]:
            message = (m[i][0][0] * modinv(s_0, n)) % n
            return b'\x00' + int_to_bytes(message)

        else:
            i += 1

def crack_challenge49A():
    server = Challenge49ServerA()
    other_client = Challenge49ClientA(server, 1000000)
    victim_client = Challenge49ClientA(server, 2000000)
    attacker_client = Challenge49ClientA(server, 0)

    other_client.send_request(other_client.generate_request(attacker_client.client_id, 1000000))

    captured_request = server.eavesdrop_request()
    target_message = captured_request['message']
    target_iv = captured_request['iv']
    target_xor = bytes([i^m for i,m in zip(target_iv, target_message)])

    mal_message = bytes('from=#{}&to=#{}&amount=#{}'.format(victim_client.client_id,
                                                                  attacker_client.client_id, 1000000), 'utf-8')
    mal_iv = bytes([x^m for x, m in zip(target_xor, mal_message)])
    mal_request = {'message': mal_message, 'iv': mal_iv, 'mac': captured_request['mac']}

    other_client.send_request(mal_request)
    assert server.ids_to_balances[attacker_client.client_id] == 2000000

def crack_challenge49B():
    server = Challenge49ServerB()
    other_client = Challenge49ClientB(server, 1000000)
    victim_client = Challenge49ClientB(server, 2000000)
    attacker_client = Challenge49ClientB(server, 0)

    victim_client.send_request(victim_client.generate_request([(other_client.client_id, 10)]))

    captured_request = server.eavesdrop_request()

    extension = bytes(';{}:1000000'.format(attacker_client.client_id), 'utf-8')
    mal_message = pkcs7pad(captured_request['message'], 16) + extension
    mal_mac = cbc_mac(captured_request['mac'], attacker_client.key, mal_message)

    mal_request = {'message': mal_message, 'mac': mal_mac}
    print(mal_request)

    attacker_client.send_request(mal_request)
    assert server.ids_to_balances[attacker_client.client_id] == 1000000

def crack_challenge50(java_code, desired_code):
    iv = (0).to_bytes(16, 'big')
    key = b'YELLOW SUBMARINE'

    forged_code = desired_code + b'//'
    space_filler = b' '*(16 - (len(forged_code) % 16))
    forged_code += space_filler
    current_mac = cbc_mac(iv, key, forged_code)
    forged_code += b'\x10'*16
    forged_code += bytes([c^j for c, j in zip(current_mac, java_code)])
    forged_code += java_code[16:]
    return forged_code


def crack_challenge51_ctr(oracle):
    valid_chars = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n')
    template = "POST / HTTP/1.1\n" \
			   "Host: hapless.com\n" \
			   "Cookie: sessionid={}\n" \
			   "Content-Length:"

    r_bytes = str([randint(0,255) for _ in range(len(template))])

    worst_compression = oracle(template.format(r_bytes), encrypt_ctr)
    ids = [('', 1 )]
    next_ids = []
    while ids:
        for prefix, compression_ratio in ids:
            for byte in valid_chars:
                candidate = prefix + byte
                c_length = oracle(template.format(candidate)*10, encrypt_ctr)
                ratio = c_length / worst_compression

                if ratio < compression_ratio+0.1:
                    if candidate[-7:] == 'Content':
                        return candidate[:-7]

                    next_ids.append((candidate, ratio))


        ids = sorted(list(next_ids), key=lambda x: x[1])
        if len(ids) > 50:
            median_compression = ids[len(ids)//2][1]
            ids = list(filter(lambda x: x[1] <= median_compression, ids))

        average_compression = sum([i[1] for i in ids]) / len(ids)
        ids = list(filter(lambda x: x[1] <= average_compression, ids))

        next_ids = []

    raise Exception("Unable to discover session id")


def crack_challenge51_cbc(oracle):
    valid_chars = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n')
    template = "POST / HTTP/1.1\n" \
			   "Host: hapless.com\n" \
			   "Cookie: sessionid={}\n" \
			   "Content-Length:"

    r_bytes = str([randint(0,255) for _ in range(len(template))])

    worst_compression = oracle(template.format(r_bytes), encrypt_ctr)
    ids = [('', 1 )]
    next_ids = []
    while ids:
        for prefix, compression_ratio in ids:
            for byte in valid_chars:
                candidate = prefix + byte
                c_length = oracle(template.format(candidate*32)*10, encrypt_ctr)
                ratio = c_length / worst_compression

                if ratio < compression_ratio+0.1:
                    if candidate[-7:] == 'Content':
                        return candidate[:-7]

                    next_ids.append((candidate, ratio))

        ids = sorted(list(next_ids), key=lambda x: x[1])[:200]
        average_compression = sum([i[1] for i in ids]) / len(ids)
        ids = list(filter(lambda x: x[1] <= average_compression, ids))

        next_ids = []

    raise Exception("Unable to discover session id")

def gen_collisions(hash_func, m, n):
    collisions = defaultdict(list)
    while True:
        msg = m.to_bytes(16, 'big')
        hash = hash_func(m=msg)

        collisions[hash].append(msg)
        if len(collisions[hash]) == 2**n:
            return (hash, collisions[hash])

        m += 1

def crack_challenge52(hash_func, f, g):
    m=0
    while True:
        collisions = gen_collisions(f, m, 12)

        g_collisions = defaultdict(list)
        for collision in collisions[1]:
            hash = g(collision)
            g_collisions[hash].append(collision)

            if len(g_collisions[hash]) == 2:
                return g_collisions[hash]

def gen_message_set(k, block_length, hash_func):
    num_blocks = k - 1
    initial_state = b'\x00' * block_length
    dummy_blocks = b'\x00' * (block_length * (2**num_blocks))
    dummy_hash = hash_func(m=dummy_blocks, h=initial_state)
    short_map = defaultdict(list)
    long_map = defaultdict(list)
    message_set = []
    m=0
    while num_blocks >= 0:
        msg = m.to_bytes(block_length, 'big')
        hash = hash_func(m=msg, h=initial_state)
        short_map[hash].append(msg)
        if long_map[hash] != []:
            message_set.append((initial_state, hash, short_map[hash][0], long_map[hash][0]))
            if num_blocks == 0:
                return message_set
            initial_state = hash
            num_blocks -= 1
            dummy_blocks = b'\x00' * (block_length * (int(2 ** num_blocks)))
            dummy_hash = hash_func(m=dummy_blocks, h=initial_state)
            short_map = defaultdict(list)
            long_map = defaultdict(list)
            m=0

        hash = hash_func(m=msg, h=dummy_hash)
        long_map[hash].append(dummy_blocks+msg)
        if short_map[hash] != []:
            message_set.append((initial_state, hash, short_map[hash][0], long_map[hash][0]))
            if num_blocks == 0:
                return message_set
            initial_state = hash
            num_blocks -= 1
            dummy_blocks = b'\x00' * (block_length * (2 ** num_blocks))
            dummy_hash = hash_func(m=dummy_blocks, h=initial_state)
            short_map = defaultdict(list)
            long_map = defaultdict(list)
            m=0

        m+=1

    return message_set

def crack_challenge53(m, k, block_length, func):
    m_map = {}
    hash = b'\x00'*block_length
    for index, m_i in enumerate(breakup_data(m, block_length)):
        hash = func(m=m_i, h=hash)
        m_map[hash] = index

    message_set = gen_message_set(k, block_length, func)
    expandable_final_state = message_set[-1][1]

    for bridge in range(2**(block_length*8)):
        bridge_block = bridge.to_bytes(block_length, 'big')
        h_i = func(m=bridge_block, h=expandable_final_state)
        index = m_map.get(h_i)

        if index:
            break

    index = m_map[h_i]
    prefix = b''
    for i in message_set:
        if len(i[3]) < ((index+1)*block_length - len(prefix)):
            prefix += i[3]
        elif len(i[2]) < ((index+1)*block_length - len(prefix)):
            prefix += i[2]
        else:
            break
    return prefix + bridge_block + m[(index+1)*block_length:]


def crack_challenge54(messages, k, block_length, hash_func):
    initial_hashes = [hash_func(m=b.to_bytes(block_length, 'big'), h=b'\x00'*block_length) for b in range(2**k)]
    funnel_map = {}
    hashes = list(initial_hashes)
    while len(hashes) > 1:
        new_hash_set = []
        for h1, h2 in zip(hashes[0::2], hashes[1::2]):
            m = 0
            hash_map = {}
            collision_found = False
            while not collision_found:
                msg = m.to_bytes(block_length, 'big')
                hash = hash_func(m=msg, h=h1)

                if hash_map.get(hash):
                    funnel_map[h1] = msg
                    ch, cm = hash_map[hash]
                    funnel_map[ch] = cm
                    new_hash_set.append(hash)
                    collision_found=True
                    continue
                else:
                    hash_map[hash] = (h1, msg)

                hash = hash_func(m=msg, h=h2)
                if hash_map.get(hash):
                    funnel_map[h2] = msg
                    ch, cm = hash_map[hash]
                    funnel_map[ch] = cm
                    new_hash_set.append(hash)
                    collision_found=True
                    continue
                else:
                    hash_map[hash] = (h2, msg)

                m += 1

        hashes = new_hash_set

    [final_state] = hashes
    forged_messages = []
    for message in messages:
        message_hash = hash_func(m=message, h=b'\x00'*block_length)
        m = 0
        while hash_func(m.to_bytes(block_length, 'big'), h=message_hash) not in initial_hashes:
            m += 1

        forged_message = message + m.to_bytes(block_length, 'big')
        forged_hash = hash_func(forged_message, h=b'\x00'*block_length)
        while funnel_map.get(forged_hash):
            block = funnel_map[forged_hash]
            forged_message += block
            forged_hash = hash_func(m=block, h=forged_hash)
        forged_hash = hash_func(forged_message, h=b'\x00'*block_length)
        forged_messages.append((forged_message, forged_hash))

    return forged_messages


