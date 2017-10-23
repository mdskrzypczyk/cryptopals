import socket
from pyasn1.codec.native.encoder import encode
from pyasn1.codec.ber import decoder as ber_decoder
from random import randint
from asn.pkcs_15_signature import DigestInfo, Digest, DigestAlgorithmIdentifier
from cipher_tools.encryption import encrypt_cbc, encrypt_rsa
from cipher_tools.decryption import decrypt_cbc
from cipher_tools.hashing import sha1, sha256, md4
from cipher_tools.mac import hmac
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
    'P': b'alligator'
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
        uH = sha256(my_byte_pub + other_byte_pub)
        self.u = int.from_bytes(uH, byteorder = 'big') 

    def generate_K(self, salt):
        self.salt = salt
        xH = sha256(salt.to_bytes(int(salt.bit_length()/4) + 1, 'big') + self.P)
        x = int.from_bytes(xH, byteorder='big')
        S = modexp(self.other_pub - self.k * modexp(self.g, x, self.N), self.prv + self.u * x, self.N)
        self.K = sha256(S.to_bytes(int(S.bit_length()/4)+1, 'big'))

    def get_HMAC_K(self):
        salt_bytes = self.salt.to_bytes(4, 'big')
        return hmac(sha256, self.K, salt_bytes, 32)

class SRPServer(DiffieHellmanClient):
    def __init__(self, config=SRP_config):
        self.__dict__.update(config)
        self.salt = randint(0, 0xFFFFFFFF)
        xH = sha256(self.salt.to_bytes(int(self.salt.bit_length()/4) + 1, 'big') + self.P)
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
        uH = sha256(other_byte_pub + my_byte_pub)
        self.u = int.from_bytes(uH, byteorder = 'big')

    def generate_K(self):
        S = modexp(self.other_pub * modexp(self.v, self.u, self.N), self.prv, self.N)
        self.K = sha256(S.to_bytes(int(S.bit_length()/4)+1, 'big'))

    def check_HMAC_K(self, HMAC):
        salt_bytes = self.salt.to_bytes(4, 'big')
        return HMAC == hmac(sha256, self.K, salt_bytes, 32)

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

challenge37_host = ''
challenge37_port = 1337
def challenge37_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((challenge37_host, challenge37_port))
        client = SRPClient()

        email, c_pub = client.email_and_pub()

        # Zero key
        mal_pub = client.N * 1
        client.pub = mal_pub
        c_pub = mal_pub

        pub_size = int(client.N.bit_length() / 4) + 1
        data = email + c_pub.to_bytes(pub_size, 'big')
        s.send(data)

        data = s.recv(1024)
        byte_salt = data[:4]
        byte_s_pub = data[4:]
        salt = int.from_bytes(byte_salt, 'big')
        s_pub = int.from_bytes(byte_s_pub, 'big')
        client.compute_uH(s_pub)
        client.generate_K(salt)

        # Because mal_pub % N == 0 we can predict what the hmac will be
        mal_hmac = hmac(sha256, sha256((0).to_bytes(int((0).bit_length() / 4) + 1, 'big')), byte_salt, 32)

        s.send(mal_hmac)
        resp = s.recv(1024)
        if resp == b'OK':
            print("SUCCESS")

def challenge37_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((challenge37_host, challenge37_port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            server = SRPServer()

            salt, s_pub = server.salt_and_pub()
            pub_size = int(server.N.bit_length() / 4) + 1
            data = salt.to_bytes(4, 'big') + s_pub.to_bytes(pub_size, 'big')
            conn.send(data)

            data = conn.recv(1024)
            email = data[:len(server.I)]
            byte_c_pub = data[len(server.I):]
            c_pub = int.from_bytes(byte_c_pub, 'big')

            server.compute_uH(c_pub)
            server.generate_K()

            hmac = conn.recv(1024)
            if server.check_HMAC_K(hmac):
                conn.send(b'OK')
            else:
                conn.send(b'BAD')

class SimplifiedSRPClient(SRPClient):
    def __init__(self, config=SRP_config):
        super(SimplifiedSRPClient, self).__init__()

    def generate_K(self, salt, other_pub, u):
        self.other_pub = other_pub
        self.salt = salt
        xH = sha256(salt.to_bytes(int(salt.bit_length()/4) + 1, 'big') + self.P)
        x = int.from_bytes(xH, byteorder='big')
        S = modexp(self.other_pub, self.prv + u*x, self.N)
        self.K = sha256(S.to_bytes(int(S.bit_length()/4)+1, 'big'))

    def get_HMAC(self):
        salt_bytes = self.salt.to_bytes(int(self.salt.bit_length() / 4) + 1, 'big')
        return hmac(sha256, self.K, salt_bytes, 32)

class SimplifiedSRPServer(SRPServer):
    def __init__(self, config=SRP_config):
        super(SimplifiedSRPServer, self).__init__()

    def salt_pub_and_random(self):
        self._generate_keypair()
        self.u = randint(0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        return self.salt, self.pub, self.u

    def generate_K(self, other_pub):
        self.other_pub = other_pub
        S = modexp(self.other_pub * modexp(self.v, self.u, self.N), self.prv, self.N)
        self.K = sha256(S.to_bytes(int(S.bit_length()/4)+1, 'big'))

    def check_HMAC(self, HMAC):
        salt_bytes = self.salt.to_bytes(int(self.salt.bit_length() / 4) + 1, 'big')
        return HMAC == hmac(sha256, self.K, salt_bytes, 32)


def challenge38_protocol():
    client = SimplifiedSRPClient()
    server = SimplifiedSRPServer()

    email, c_pub = client.email_and_pub()
    salt, s_pub, u = server.salt_pub_and_random()
    # Mal server returns salt, s_pub, u
    mal_salt = 0
    mal_s_pub = server.g
    mal_u = 1

    client.generate_K(mal_salt, mal_s_pub, mal_u)
    server.generate_K(c_pub)

    c_hmac = client.get_HMAC()
    with open('/usr/share/dict/words') as f:
        for w in f:
            p = w.rstrip()
            p = bytes(p, 'utf-8')
            xH = sha256(b'\x00' + p)
            x = int.from_bytes(xH, byteorder='big')
            S = c_pub * modexp(server.g, x, server.N) % server.N
            K = sha256(S.to_bytes(int(S.bit_length() / 4) + 1, 'big'))
            h_K = hmac(sha256, K, b'\x00', 32)
            if c_hmac == h_K:
                return p
        i += 1

    return server.check_HMAC(hmac)

def pkcs15sigverify(message, signature, public_key):
    # "Encrypt" the data with public key to get the signed data
    data = b'\x00' + encrypt_rsa(signature, public_key[0], public_key[1])

    # Verify the initial 00 01 ff
    if data[0:3] != b'\x00\x01\xff':
        return False

    # Search for where the ASN.1 data starts, assume octet 4 could be 00
    right_start = 4
    for i, b in enumerate(data[3:]):
        if b == 0xFF:
            continue
        elif b == 0x00:
            right_start += i
            break
        else:
            return False

    # Obtain the ASN.1 and HASH data
    right_justified_segment = data[right_start:]

    # Get the ASN.1 information
    digest_info = encode(ber_decoder.decode(right_justified_segment, asn1Spec=DigestInfo())[0])
    try:
        if digest_info['digestAlgorithm']['algorithm'] != '1.2.840.113549.1.1.4':
            return False
    except:
        return False

    # Compute HASH
    computed_hash = md4(message)

    # Verify the HASH
    message_digest = digest_info['digest']
    for b1, b2 in zip(computed_hash, message_digest):
        if b1 != b2:
            return False

    return True

