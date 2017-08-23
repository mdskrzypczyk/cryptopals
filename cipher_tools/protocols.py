from hashlib import sha256
from random import randint
from cipher_tools.encryption import encrypt_cbc
from cipher_tools.decryption import decrypt_cbc
from cipher_tools.hashing import sha1
from cipher_tools.mathlib import diffie_hellman, generate_dh_keypair, modexp

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

SRP_config = {
    'N': 0xf0155ced0c53bd6f58cd1644f0276d3198123ec3ec86f28388a5f7161f61491f97a99ac6765de691dd59b16e43f5177541042cffddc7ce5c0fbfd11743710da5d52101d4c63ad1442f2405f1fcf36082bc1aa9b9708f1cbc8e7471e5443d301da07443f81a0800091bde0e149e4743ecbfefe30efde37a5f83b308cc23b573eb,
    'g': 2,
    'k': 3,
    'I': b'foo@bar.com',
    'P': b'deadbeef'
}

class SRPClient(DiffieHellmanClient):
    def __init__(self, config=SRP_config):
        self.__dict__.update(config)
        super(SRPClient, self).__init__(name='srp_client', p=self.N, g=self.g)

    def email_and_pub(self):
        self._generate_keypair()
        return self.I, self.pub

    def compute_uH(self, other_pub):
        self.other_pub = other_pub
        my_byte_pub = self.pub.to_bytes(int(self.pub.bit_length()/4) + 1, 'big')
        other_byte_pub = other_pub.to_bytes(int(other_pub.bit_length()/4) + 1, 'big')
        m = sha256()
        m.update(my_byte_pub + other_byte_pub)
        uH = m.digest()
        self.u = int.from_bytes(uH, byteorder = 'big') 

    def generate_K(self, salt):
        m = sha256()
        m.update(salt.to_bytes(int(salt.bit_length()/4) + 1, 'big') + self.I)
        xH = m.digest()
        x = int.from_bytes(xH, byteorder='big')
        S = modexp(self.other_pub - self.k * modexp(self.g, x, self.N), self.prv + self.u * x, self.N)
        m = sha256()
        m.update(S.to_bytes(int(S.bit_length()/4)+1, 'big'))
        self.K = m.digest()

    def get_HMAC_K(self):
        m = sha256()
        m.update(self.K)
        return m.digest()

class SRPServer(DiffieHellmanClient):
    def __init__(self, config=SRP_config):
        self.__dict__.update(config)
        m = sha256()
        self.salt = randint(0, 0xFFFFFFFF)
        m.update(self.salt.to_bytes(int(self.salt.bit_length()/4) + 1, 'big') + self.I)
        xH = m.digest()
        x = int.from_bytes(xH, byteorder = 'big')
        self.v = modexp(self.g, x, self.N)
        super(SRPServer, self).__init__(name='srp_server', p=self.N, g=self.g)

    def salt_and_pub(self):
        self._generate_keypair()
        self.pub = self.k * self.v + self.pub
        return self.salt, self.pub

    def compute_uH(self, other_pub):
        self.other_pub = other_pub
        my_byte_pub = self.pub.to_bytes(int(self.pub.bit_length()/4) + 1, 'big')
        other_byte_pub = other_pub.to_bytes(int(other_pub.bit_length()/4) + 1, 'big')
        m = sha256()
        m.update(other_byte_pub + my_byte_pub)
        uH = m.digest()   
        self.u = int.from_bytes(uH, byteorder = 'big')

    def generate_K(self):
        S = modexp(self.other_pub * modexp(self.v, self.u, self.N), self.prv, self.N)
        m = sha256()
        m.update(S.to_bytes(int(S.bit_length()/4)+1, 'big'))
        self.K = m.digest()

    def check_HMAC_K(self, HMAC):
        m = sha256()
        m.update(self.K)
        return HMAC == m.digest()

def challenge36_protocol():
    client = SRPClient()
    server = SRPServer()

    email, c_pub = client.email_and_pub()
    salt, s_pub = server.salt_and_pub()
   
    client.compute_uH(s_pub)
    server.compute_uH(c_pub)

    client.generate_K(salt)
    server.generate_K()

    hmac = client.get_HMAC_K()
    return server.check_HMAC_K(hmac)
