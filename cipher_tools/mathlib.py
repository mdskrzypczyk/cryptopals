english_freq = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,                   # V-Z
]

def getChi2_english(text):
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

def hamming_distance(string1, string2):
    distance = 0
    string1 += bytes(len(string2) - len(string1))
    string2 += bytes(len(string1) - len(string2))
    for c1, c2 in zip(string1, string2):
        xor = c1 ^ c2
        bin_diff = bin(xor)
        distance += bin_diff.count('1')
    return distance