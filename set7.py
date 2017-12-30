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

def challenge52():
    pass