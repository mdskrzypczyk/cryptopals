from cipher_tools.mathlib import generate_dh_keypair, diffie_hellman
def challenge33(p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff, g=2):
    a, A = generate_dh_keypair(p, g)
    b, B = generate_dh_keypair(p, g)
    sa = diffie_hellman(p, B, a)
    sb = diffie_hellman(p, A, b)
    assert sa == sb
    return sa

from cipher_tools.protocols import DiffieHellmanClient, challenge34_protocol
from cipher_tools.cracking import mitm_dh_wire
def challenge34():
    clientA = DiffieHellmanClient(name="Alice")
    clientB = DiffieHellmanClient(name="Bob")
    challenge34_protocol(clientA, clientB, wire={})
    challenge34_protocol(clientA, clientB, wire=mitm_dh_wire())

from cipher_tools.protocols import challenge35_protocol
def challenge35():
    clientA = DiffieHellmanClient(name="Alice")
    clientB = DiffieHellmanClient(name="Bob")
    challenge35_protocol(clientA, clientB, wire={})
    dh_group = {'p': 37, 'g': 1}
    print(dh_group) 
    challenge35_protocol(clientA, clientB, wire=mitm_dh_wire(dh_group))
    dh_group['g'] = dh_group['p']
    print(dh_group)
    challenge35_protocol(clientA, clientB, wire=mitm_dh_wire(dh_group))
    dh_group['g'] = dh_group['p'] - 1
    print(dh_group)
    challenge35_protocol(clientA, clientB, wire=mitm_dh_wire(dh_group))

from cipher_tools.protocols import challenge36_protocol
def challenge36():
    return challenge36_protocol()

def challenge37():
    pass

def challenge38():
    pass

def challenge39():
    pass

def challenge40():
    pass
