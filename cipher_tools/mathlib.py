from Crypto.Util import number
from random import randint, randrange

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

def modexp(g, u, p):
    s = 1
    while u != 0:
        if u & 1:
            s = (s * g) % p
        u >>= 1
        g = (g * g) % p
    return s

def generate_dh_keypair(p, g):
    a = randint(0, p - 1)
    A = modexp(g, a, p)
    return (a, A)

def diffie_hellman(p, B, a):
    # Calculate shared secret
    s = modexp(B, a, p)
    return s

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def gen_rsa_keys():
    p, q = number.getPrime(512), number.getPrime(512)
    n = p * q
    et = ((p - 1) * (q - 1)) % n
    e = 3
    d = modinv(e, et)
    return ((e, n), (d,n))

def find_cube_root(n):
    lo = 0
    hi = n
    while lo < hi:
        mid = (lo+hi)//2
        if mid**3 < n:
            lo = mid+1
        else:
            hi = mid
    return lo

def three_residue_crt(c0, n0, c1, n1, c2, n2):
    ms0 = n1 * n2
    ms1 = n0 * n2
    ms2 = n0 * n1
    res = ((c0 * ms0 * modinv(ms0, n0)) + (c1 * ms1 * modinv(ms1, n1)) + (c2 * ms2 * modinv(ms2, n2)))
    res = res % (n0 * n1 * n2)
    return find_cube_root(res)
