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

def challenge19():
    pass

def challenge20():
    pass

def challenge21():
    pass

def challenge22():
    pass

def challenge23():
    pass

def challenge24():
    pass
