from string import ascii_lowercase, ascii_uppercase

def single_byte_xor(data, byte):
    return [d ^ byte for d in data]

def single_byte_xor_map(data):
    xor_data = {}
    data = [ord(a) for a in ascii]
    for c in range(256):
        
        hex_c = '0'*(2-len(hex(c)[2:])) + hex(c)[2:]
        c_string = hex_c*int(len(target_string) / 2)
        x_string = xor_hex_strings(target_string, c_string)
        a_string = ''.join([chr(int(x_string[i:i+2],16)) for i in range(0, len(x_string),2)])
        decrypted_ciphers[a_string] = chr(c)
    return decrypted_ciphers

def get_ascii_decryptions(target_string):
    decrypted = xor_with_all_characters(target_string)
    ascii_decryptions = {}
    for d in decrypted.keys():
        ascii = [c for c in d if len(c) == len(c.encode())]
        if len(ascii) == len(d):
            ascii_decryptions[d] = decrypted[d]

    return ascii_decryptions

def decrypt_one_char_xor(hex_string):
    decryptions = get_ascii_decryptions(hex_string)
    sorted_d = sorted(decryptions.items(), key=lambda x : getChi2(x[0]))
    decryptions = list(filter(lambda x : getChi2(x[0]) != float('inf'), sorted_d))
    if decryptions:
        return decryptions[0]
    else:
        return None

#print(decrypt_one_char_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
