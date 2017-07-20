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

def challenge27():
    pass

def challenge28():
    pass

def challenge29():
    pass

def challenge30():
    pass

def challenge31():
    pass

def challenge32():
    pass

