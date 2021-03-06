from cipher_tools.cracking import crack_challenge41
def challenge41():
    return crack_challenge41()

from cipher_tools.cracking import crack_challenge42
from cipher_tools.protocols import pkcs15sigverify
def challenge42():
    message = b'hi mom'
    signature, pub_key = crack_challenge42(message)
    return pkcs15sigverify(message, signature, pub_key)

dsa_params = {
    'p': int('800000000000000089e1855218a0e7dac38136ffafa72eda7'
             '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
             '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
             'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
             'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
             '1a584471bb1', 16),
    'g': int('5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
             '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
             '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
             '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
             '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
             '9fc95302291', 16),
    'q': int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)
}
from cipher_tools.cracking import crack_challenge43
def challenge43():
    message = b'For those that envy a MC it can be hazardous to your health\n' \
              b'So be friendly, a matter of life and death, just like a etch-a-sketch\n'
    signature = (548099063082341131477253921760299949438196259240, 857042759984254168557880549501802188789837994940)
    return crack_challenge43(message, signature, dsa_params)

from cipher_tools.data_manipulation import grouper
from cipher_tools.cracking import crack_challenge44
def challenge44():
    with open('challenge_data/challenge44.txt') as f:
        data = f.read().split('\n')
    challenge_data = []
    for data_segment in grouper(data, 4):
        msg_data = {
            'msg': bytes(data_segment[0].split(': ')[1] + ' ', 'utf-8'),
            's': int(data_segment[1].split(': ')[1]),
            'r': int(data_segment[2].split(': ')[1]),
            'm': int(data_segment[3].split(': ')[1], 16)
        }
        challenge_data.append(msg_data)
    return crack_challenge44(challenge_data, dsa_params)

from random import randint
from cipher_tools.hashing import sha1
from cipher_tools.mathlib import gen_rsa_keys, modexp
from cipher_tools.dsa import dsa_sign, dsa_sig_verify
from cipher_tools.cracking import generate_magic_signature
def challenge45():
    tampered_params = dict(dsa_params)
    tampered_params['g'] = 0
    pub_key = randint(1, tampered_params['q'] - 1)
    priv_key = modexp(tampered_params['g'], pub_key, tampered_params['p'])
    msg1, msg2 = 2, b'Hello, world', b'Goodbye, world'
    # dsa implementation causes r = 0 signatures to be invalid
    # sig = dsa_sign(msg1, priv_key, tampered_params, sha1)
    # dsa_sig_verify(msg1, sig, pub_key, tampered_params, sha1)
    tampered_params['g'] = tampered_params['p'] + 1
    signature = generate_magic_signature(pub_key, tampered_params)
    return [(msg1, signature, dsa_sig_verify(msg1, signature, pub_key, tampered_params, sha1)),
            (msg2, signature, dsa_sig_verify(msg2, signature, pub_key, tampered_params, sha1))]

from cipher_tools.cracking import crack_challenge46
from cipher_tools.oracles import challenge46_oracle, challenge46_cipher, challenge46_pub
def challenge46():
    return crack_challenge46(challenge46_cipher, challenge46_pub, challenge46_oracle)

from cipher_tools.oracles import challenge47_cipher, challenge47_pub, challenge47_oracle
from cipher_tools.cracking import crack_challenge47
def challenge47():
    return crack_challenge47(challenge47_cipher, challenge47_pub, challenge47_oracle)

from cipher_tools.oracles import challenge48_cipher, challenge48_pub, challenge48_oracle
from cipher_tools.cracking import crack_challenge47
def challenge48():
    return crack_challenge47(challenge48_cipher, challenge48_pub, challenge48_oracle)
