def hmac(h, K, m, blocksize):
    key = K
    if len(K) > blocksize:
        key = h(K)
    if len(K) < blocksize:
        key = K + b'\x00'*(blocksize - len(K))

    o_key_pad = bytes([0x5C ^ k for k in key])
    i_key_pad = bytes([0x36 ^ k for k in key])
    return h(o_key_pad + h(i_key_pad + m))