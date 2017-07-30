import struct
from cipher_tools.data_manipulation import breakup_data, left_rotate
from cipher_tools.padding import sha1pad, sha1pad_verify

def sha1(message, message_len=None, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F):
    if message_len:
        num_bytes = int(message_len/8)
        pad_len = -num_bytes % 64
        message += b'\x80' + b'\x00'*(pad_len-9) + message_len.to_bytes(8, 'big')
    else:
        message = sha1pad(message)

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
