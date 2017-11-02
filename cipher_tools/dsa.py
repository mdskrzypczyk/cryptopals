from random import randint
from cipher_tools.mathlib import modexp, modinv

def dsa_generate_params():
    pass

def dsa_calculate_signature(k, h, private_key, params):
    p = params['p']
    g = params['g']
    q = params['q']

    r = modexp(g, k, p) % q
    s = (modinv(k, q) * (h + private_key * r)) % q
    return r, s

def dsa_sign(message, private_key, params, hashing_func):
    q = params['q']
    r, s = 0, 0
    while r == 0 or s == 0:
        k = randint(2, q -1)
        h = int.from_bytes(hashing_func(message), 'big')
        r, s = dsa_calculate_signature(k, h, private_key, params)

    return (r, s)

def dsa_sig_verify(message, signature, public_key, params, hashing_func):
    p = params['p']
    g = params['g']
    q = params['q']

    r, s = signature
    if r not in range(1, q - 1) or s not in range(1, q - 1):
        return False

    print("Verifying")
    w = modinv(s, q)
    h = int.from_bytes(hashing_func(message), 'big')

    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((modexp(g, u1, p) * modexp(public_key, u2, p)) % p) % q
    print(v)
    return v == r