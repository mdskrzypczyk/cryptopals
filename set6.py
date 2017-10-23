from cipher_tools.cracking import crack_challenge41
def challenge41():
    return crack_challenge41()

from cipher_tools.cracking import crack_challenge42
from cipher_tools.protocols import pkcs15sigverify
def challenge42():
    message = b'hi mom'
    signature, pub_key = crack_challenge42(message)
    return pkcs15sigverify(message, signature, pub_key)

def challenge43():
    pass

def challenge44():
    pass

def challenge45():
    pass

def challenge46():
    pass

def challenge47():
    pass

def challenge48():
    pass
