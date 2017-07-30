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

from cipher_tools.padding import sha1pad, sha1pad_verify
from cipher_tools.cracking import length_extend_sha1
def challenge29(message=b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"):
    msg_sha = sha1(message)
    msg_len = len(message)*8
    msg_len = msg_len + (-msg_len % 512)
    mal_extension = b";admin=true;"
    dub_msg_sha = sha1(sha1pad(message) + mal_extension)
    return length_extend_sha1(msg_sha, msg_len, mal_extension) == dub_msg_sha

def challenge30():
    pass

def challenge31():
    pass

def challenge32():
    pass

