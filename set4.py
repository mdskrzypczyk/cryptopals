from cipher_tools.oracles import challenge25_oracle
from cipher_tools.oracles import challenge25_edit
from cipher_tools.cracking import crack_challenge25_oracle
def challenge25():
    return crack_challenge25_oracle(challenge25_oracle, challenge25_edit)

from cipher_tools.oracles import challenge26_oracle, challenge26_check_answer
from cipher_tools.cracking import crack_challenge26_oracle
def challenge26():
    crafted = crack_challenge26_oracle(challenge26_oracle)
    return challenge26_check_answer(crafted)

from cipher_tools.oracles import challenge27_oracle, challenge27_check_answer
from cipher_tools.cracking import crack_challenge27_oracle
def challenge27():
    return crack_challenge27_oracle(challenge27_oracle, challenge27_check_answer)

from cipher_tools.hashing import sha1
def challenge28(data=b'abc'):
    return sha1(data)

def challenge29():
    pass

def challenge30():
    pass

def challenge31():
    pass

def challenge32():
    pass

