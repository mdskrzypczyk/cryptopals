from string import ascii_lowercase, ascii_uppercase

english_freq = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,                   # V-Z
]

def getChi2 (text):
    count = [0]*26
    ignored = 0

    for c in text:
        v = ord(c)
        # uppercase A-Z
        if v >= 65 and v <= 90:
            count[v - 65] += 1        
        elif v >= 97 and v <= 122:
            count[v - 97] += 1  # lowercase a-z
        elif v == 32:
            pass
        elif v == 94:
            return float('inf')
        elif v >= 33 and v <= 126:
            ignored += 1        # numbers and punct.
        elif v == 9 or v == 10 or v == 13:
            ignored += 1  # TAB, CR, LF
        else:
            return float("inf")  # not printable ASCII = impossible(?)
    
    chi2 = 0
    length = len(text) - ignored;
    if length == 0:
        return float('inf')
    for i in range(26):
        observed = count[i] / length
        expected = english_freq[i]
        difference = observed - expected
        chi2 += difference * difference / expected;

    return chi2;

def xor_hex_strings(hex1, hex2):
    result = ''.join(["{0:0x}".format(int(h1,16) ^ int(h2,16)) for h1,h2 in zip(hex1,hex2)])
    return result

def xor_with_all_characters(target_string):
    decrypted_ciphers = {}
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
