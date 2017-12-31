from cipher_tools.cracking import crack_challenge49A, crack_challenge49B
def challenge49():
    crack_challenge49A()
    return crack_challenge49B()

from cipher_tools.cracking import crack_challenge50
def challenge50():
    return crack_challenge50(b"alert('MZA who was that?');\n", b"alert('Ayo, the Wu is back!');\n")

from cipher_tools.cracking import crack_challenge51_ctr, crack_challenge51_cbc
from cipher_tools.oracles import challenge51_oracle
def challenge51():
    ctr_id = crack_challenge51_ctr(challenge51_oracle)
    cbc_id = crack_challenge51_cbc(challenge51_oracle)
    return ctr_id, cbc_id

from cipher_tools.cracking import crack_challenge52
from cipher_tools.oracles import challenge52_f, challenge52_g, challenge52_oracle
def challenge52():
    collisions = crack_challenge52(challenge52_oracle, challenge52_f, challenge52_g)
    return [(collision, challenge52_oracle(collision)) for collision in collisions]

from random import randint
from cipher_tools.cracking import crack_challenge53
from cipher_tools.oracles import challenge53_hasher
def challenge53():
    k = 5
    block_length = 2
    m = bytes([randint(0, 255) for _ in range(block_length * 2**k)])
    forged_m = crack_challenge53(m, k, block_length, challenge53_hasher)
    m_hash = challenge53_hasher(m=m, h=b'\x00' * block_length)
    forged_m_hash = challenge53_hasher(m=forged_m, h=b'\x00' * block_length)
    return [(m, m_hash), (forged_m, forged_m_hash)]

from cipher_tools.cracking import crack_challenge54
def challenge54():
    block_length = 2
    k = 6
    messages = [b'Winner is team #' + bytes('{}'.format(i), 'utf-8') for i in range(10,74)]
    return crack_challenge54(messages, k, block_length, challenge53_hasher)

