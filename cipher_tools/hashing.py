import struct
import hashlib
from cipher_tools.data_manipulation import breakup_data, left_rotate
from cipher_tools.padding import mdpad

def sha1(message, message_len=None, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):
    if message_len:
        num_bytes = int(message_len/8)
        pad_len = -num_bytes % 64
        message += b'\x80' + b'\x00'*(pad_len-9) + message_len.to_bytes(8, 'big')
    else:
        message = mdpad(message)
    chunks = breakup_data(message, 64)

    for chunk in chunks:
        words = [struct.unpack(">I", b)[0] for b in breakup_data(chunk, 4)]
        for i in range(16, 80):
            words.append(left_rotate(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 32, 1))
        a, b, c, d, e = h0, h1, h2, h3, h4

        for i, word in enumerate(words):
            if i in range(0,20):
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i in range(20,40):
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i in range(40,60):
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif i in range(60,80):
                f = b ^ c ^ d
                k = 0xCA62C1D6

            e, d, c, b, a = d, c, left_rotate(b, 32, 30), a, (left_rotate(a, 32, 5) + f + e + k + word) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    hh = b''.join([h.to_bytes(4, 'big') for h in [h0, h1, h2, h3, h4]])
    return hh

def sha256(message):
    h = hashlib.sha256()
    h.update(message)
    return h.digest()

def md4_f(x, y, z): return (x & y) | (~x & z)
def md4_g(x, y, z): return (x & y) | (x & z) | (y & z)
def md4_h(x, y, z): return x ^ y ^ z

def md4_round1(a, b, c, d, words):
    a = left_rotate(a + md4_f(b, c, d) + words[0], 32, 3)
    d = left_rotate(d + md4_f(a, b, c) + words[1], 32, 7)
    c = left_rotate(c + md4_f(d, a, b) + words[2], 32, 11)
    b = left_rotate(b + md4_f(c, d, a) + words[3], 32, 19)
    a = left_rotate(a + md4_f(b, c, d) + words[4], 32, 3)
    d = left_rotate(d + md4_f(a, b, c) + words[5], 32, 7)
    c = left_rotate(c + md4_f(d, a, b) + words[6], 32, 11)
    b = left_rotate(b + md4_f(c, d, a) + words[7], 32, 19)
    a = left_rotate(a + md4_f(b, c, d) + words[8], 32, 3)
    d = left_rotate(d + md4_f(a, b, c) + words[9], 32, 7)
    c = left_rotate(c + md4_f(d, a, b) + words[10], 32, 11)
    b = left_rotate(b + md4_f(c, d, a) + words[11], 32, 19)
    a = left_rotate(a + md4_f(b, c, d) + words[12], 32, 3)
    d = left_rotate(d + md4_f(a, b, c) + words[13], 32, 7)
    c = left_rotate(c + md4_f(d, a, b) + words[14], 32, 11)
    b = left_rotate(b + md4_f(c, d, a) + words[15], 32, 19)
    return (a, b, c, d, words)

def md4_round2(a, b, c, d, words):
    a = left_rotate(a + md4_g(b, c, d) + words[0] + 0x5A827999, 32, 3)
    d = left_rotate(d + md4_g(a, b, c) + words[4] + 0x5A827999, 32, 5)
    c = left_rotate(c + md4_g(d, a, b) + words[8] + 0x5A827999, 32, 9)
    b = left_rotate(b + md4_g(c, d, a) + words[12] + 0x5A827999, 32, 13)
    a = left_rotate(a + md4_g(b, c, d) + words[1] + 0x5A827999, 32, 3)
    d = left_rotate(d + md4_g(a, b, c) + words[5] + 0x5A827999, 32, 5)
    c = left_rotate(c + md4_g(d, a, b) + words[9] + 0x5A827999, 32, 9)
    b = left_rotate(b + md4_g(c, d, a) + words[13] + 0x5A827999, 32, 13)
    a = left_rotate(a + md4_g(b, c, d) + words[2] + 0x5A827999, 32, 3)
    d = left_rotate(d + md4_g(a, b, c) + words[6] + 0x5A827999, 32, 5)
    c = left_rotate(c + md4_g(d, a, b) + words[10] + 0x5A827999, 32, 9)
    b = left_rotate(b + md4_g(c, d, a) + words[14] + 0x5A827999, 32, 13)
    a = left_rotate(a + md4_g(b, c, d) + words[3] + 0x5A827999, 32, 3)
    d = left_rotate(d + md4_g(a, b, c) + words[7] + 0x5A827999, 32, 5)
    c = left_rotate(c + md4_g(d, a, b) + words[11] + 0x5A827999, 32, 9)
    b = left_rotate(b + md4_g(c, d, a) + words[15] + 0x5A827999, 32, 13)
    return (a, b, c, d, words)

def md4_round3(a, b, c, d, words):
    a = left_rotate(a + md4_h(b, c, d) + words[0] + 0x6ED9EBA1, 32, 3)
    d = left_rotate(d + md4_h(a, b, c) + words[8] + 0x6ED9EBA1, 32, 9)
    c = left_rotate(c + md4_h(d, a, b) + words[4] + 0x6ED9EBA1, 32, 11)
    b = left_rotate(b + md4_h(c, d, a) + words[12] + 0x6ED9EBA1, 32, 15)
    a = left_rotate(a + md4_h(b, c, d) + words[2] + 0x6ED9EBA1, 32, 3)
    d = left_rotate(d + md4_h(a, b, c) + words[10] + 0x6ED9EBA1, 32, 9)
    c = left_rotate(c + md4_h(d, a, b) + words[6] + 0x6ED9EBA1, 32, 11)
    b = left_rotate(b + md4_h(c, d, a) + words[14] + 0x6ED9EBA1, 32, 15)
    a = left_rotate(a + md4_h(b, c, d) + words[1] + 0x6ED9EBA1, 32, 3)
    d = left_rotate(d + md4_h(a, b, c) + words[9] + 0x6ED9EBA1, 32, 9)
    c = left_rotate(c + md4_h(d, a, b) + words[5] + 0x6ED9EBA1, 32, 11)
    b = left_rotate(b + md4_h(c, d, a) + words[13] + 0x6ED9EBA1, 32, 15)
    a = left_rotate(a + md4_h(b, c, d) + words[3] + 0x6ED9EBA1, 32, 3)
    d = left_rotate(d + md4_h(a, b, c) + words[11] + 0x6ED9EBA1, 32, 9)
    c = left_rotate(c + md4_h(d, a, b) + words[7] + 0x6ED9EBA1, 32, 11)
    b = left_rotate(b + md4_h(c, d, a) + words[15] + 0x6ED9EBA1, 32, 15)
    return (a, b, c, d)

def md4(message, message_len=None, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476):
    if message_len:
        num_bytes = int(message_len/8)
        pad_len = -num_bytes % 64
        message += b'\x80' + b'\x00'*(pad_len-9) + message_len.to_bytes(8, 'little')
    else:
        message = mdpad(message, 'little')

    chunks = breakup_data(message, 64)
    for chunk in chunks:
        words = [struct.unpack("<I", b)[0] for b in breakup_data(chunk, 4)]

        a, b, c, d, words = md4_round1(h0, h1, h2, h3, words)
        a, b, c, d, words = md4_round2(a, b, c, d, words)
        a, b, c, d = md4_round3(a, b, c, d, words)

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF

    hh = b''.join([h.to_bytes(4, 'little') for h in [h0, h1, h2, h3]])
    return hh
