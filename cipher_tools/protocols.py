from random import randint
from cipher_tools.encryption import encrypt_cbc
from cipher_tools.decryption import decrypt_cbc
from cipher_tools.hashing import sha1
from cipher_tools.mathlib import diffie_hellman, generate_dh_keypair

class DiffieHellmanClient:
    def __init__(self, name, wire=None, p=37, g=5):
        self.name = name
        self.wire = wire
        self.p = p
        self.g = g

    def add_wire(self, wire):
        self.wire = wire

    def _generate_keypair(self):
        self.prv, self.pub = generate_dh_keypair(self.p, self.g)

    def _send_ack(self, dest):
        ack = {"from": self.name, "ack": "ACK"}
        self.wire[dest] = ack

    def _recv_ack(self):
        ack = self.wire.pop(self.name)
        assert ack['ack'] == 'ACK'

    def _send_dh_group(self, dest):
        params = {"from": self.name, "p": self.p, "g": self.g}
        self.wire[dest] = params

    def _recv_dh_group(self):
        params = self.wire.pop(self.name)
        self.g = params["g"]
        self.p = params["p"]
        self._generate_keypair()

    def _send_params(self, dest):
        params = {"from": self.name, "p": self.p, "g": self.g, "pub": self.pub}
        self.wire[dest] = params

    def _recv_params(self):
        params = self.wire.pop(self.name)
        self.g = params["g"]
        self.prv, self.pub = generate_dh_keypair(self.p, self.g)
        self.ss = diffie_hellman(self.p, params["pub"], self.prv)

    def _send_pub(self, dest):
        params = {"from": self.name, "pub": self.pub}
        self.wire[dest] = params

    def _recv_pub(self):
        params = self.wire.pop(self.name)
        self.ss = diffie_hellman(self.p, params["pub"], self.prv)

    def _send_msg(self, dest, msg):
        iv = bytes([randint(0,255) for i in range(16)])
        key = sha1(self.ss.to_bytes(int(self.ss.bit_length()/4)+1, byteorder='big'))[0:16]
        cipher = encrypt_cbc(iv, key, msg, pad=True)
        self.wire[dest] = {"from": self.name, "msg": (cipher, iv)}

    def _recv_msg(self):
        cipher, iv = self.wire.pop(self.name).pop("msg")
        key = sha1(self.ss.to_bytes(int(self.ss.bit_length()/4)+1, byteorder='big'))[0:16]
        msg = decrypt_cbc(iv, key, cipher, pad=True)
        return msg

    def _reply_msg(self, dest):
        msg = self._recv_msg()
        self._send_msg(dest, msg)

def challenge34_protocol(clientA, clientB, wire):
    clientA.add_wire(wire)
    clientB.add_wire(wire)
    clientA._generate_keypair()
    clientA._send_params(clientB.name)

    clientB._recv_params()
    clientB._send_pub(clientA.name)

    clientA._recv_pub()

    for msg_round in range(10):
        msg = bytes([randint(0,255) for i in range(randint(0, 100))])
        clientA._send_msg(clientB.name, msg)

        clientB._reply_msg(clientA.name)
        recv_msg = clientA._recv_msg()
        assert msg == recv_msg

def challenge35_protocol(clientA, clientB, wire):
    clientA.add_wire(wire)
    clientB.add_wire(wire)
    clientA._generate_keypair()
    clientA._send_dh_group(clientB.name)

    clientB._recv_dh_group()
    clientB._send_ack(clientA.name)

    clientA._recv_ack()
    clientA._send_pub(clientB.name)

    clientB._recv_pub()
    clientB._send_pub(clientA.name)

    clientA._recv_pub()

    for msg_round in range(10):
        msg = bytes([randint(0,255) for i in range(randint(0, 100))])
        clientA._send_msg(clientB.name, msg)

        clientB._reply_msg(clientA.name)
        recv_msg = clientA._recv_msg()
        assert msg == recv_msg
