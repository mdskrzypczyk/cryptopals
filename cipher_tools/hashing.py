import struct
from cipher_tools.data_manipulation import breakup_data, left_rotate

def sha1(message):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    ml = len(message)*8

    message += b'\x80'
    pad = b'\x00'*(-(len(message) + 8) % 64)
    message += pad + len(message).to_bytes(8, 'big')
    print(message)
    print(len(message))

    chunks = breakup_data(message, 64)
    print(chunks)
    for chunk in chunks:
        words = [struct.unpack("<I", b)[0] for b in breakup_data(chunk, 4)]
        for i in range(16,80):
            words.append(left_rotate(words[i-3] ^ words[i-8] ^ words[i-16], 32, 1))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for word, i in enumerate(words):
            if i in range(0,20):
                f = (b & c) | (not(b) & 0xFFFFFFFF & d)
                k = 0x5A827999
            elif i in range(20,40):
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i in range(40,60):
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 32, 5) + f + e + k + word) & 0xFFFFFFFF
            e = d
            d = c
            c = left_rotate(b, 32, 30)
            b = a
            a = temp

        h0 = (h0 + a & 0xFFFFFFFF)
        h1 = (h1 + b & 0xFFFFFFFF)
        h2 = (h2 + c & 0xFFFFFFFF)
        h3 = (h3 + d & 0xFFFFFFFF)
        h4 = (h4 + e & 0xFFFFFFFF)

    print(h0,h1,h2,h3,h4)

    hh = b''.join([h.to_bytes(4, 'big') for h in [h0, h1, h2, h3, h4]])
    print(len(hh))
    return hh
