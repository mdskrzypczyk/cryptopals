from cipher_tools.cracking import crack_challenge17_oracle
from cipher_tools.oracles import challenge17_iv, challenge17_cipher, challenge17_oracle
def challenge17():
    return crack_challenge17_oracle(challenge17_oracle, challenge17_iv, challenge17_cipher)

from base64 import b64decode
from cipher_tools.decryption import decrypt_ctr
def challenge18():
    nonce = bytes(16)
    key = b'YELLOW SUBMARINE'
    data = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    return decrypt_ctr(nonce, key, data)

from cipher_tools.cracking import crack_common_nonce_ctr
from cipher_tools.oracles import get_challenge19_cipherset
def challenge19():
    return crack_common_nonce_ctr(get_challenge19_cipherset())

from cipher_tools.cracking import crack_common_nonce_ctr_via_stats
from cipher_tools.oracles import get_challenge20_cipherset
def challenge20():
    return crack_common_nonce_ctr_via_stats(get_challenge20_cipherset())

from cipher_tools.rng import mersenne_twister_rng, MT19937_config
def challenge21(seed = 5489):
    return [hex(mersenne_twister_rng(seed, MT19937_config, i)) for i in range(MT19937_config['n'])]


from cipher_tools.oracles import challenge22_oracle
from cipher_tools.cracking import crack_challenge22_oracle
def challenge22():
    return crack_challenge22_oracle(challenge22_oracle)

from cipher_tools.cracking import mersenne_twister_untemper
def challenge23(seed = 5489):
    rng_output = [mersenne_twister_rng(seed, MT19937_config, i) for i in range(624)]
    recovered_state = [mersenne_twister_untemper(o, MT19937_config) for o in rng_output]
    return recovered_state

from cipher_tools.oracles import challenge24_oracle
from cipher_tools.cracking import crack_challenge24_oracle
def challenge24():
    return crack_challenge24_oracle(challenge24_oracle)
