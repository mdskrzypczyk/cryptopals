import operator
from challenge18 import *
from base64 import b64decode

nonce = bytes(16)
key = bytes([randint(0, 15) for i in range(16)])
dataset = [b64decode(d) for d in open('19.txt').read().splitlines()]

def recover_key_pairs(cipher1, cipher2):
    pos = 0
    index_key_pairs = {}
    for c1, c2 in zip(cipher1, cipher2):
        p = bytes([c1^c2])
        if p.isupper() or p.islower():
            index_key_pairs[pos] = (c1^32, c2^32)
        pos += 1
    return index_key_pairs

def crack_ctr_key_via_spaces(cipherset):
    recovered_key_dict = {}
    for cipher1 in cipherset:
        for cipher2 in cipherset - set([cipher1]):
            recovered_pairs = recover_key_pairs(cipher1, cipher2)
            for index, k in recovered_pairs.items():
                k1, k2 = k
                if index not in recovered_key_dict.keys():
                    recovered_key_dict[index] = {k1: 1, k2: 1}

                else:
                    index_key_dict = recovered_key_dict[index]
                    
                    if k1 in index_key_dict.keys():
                        index_key_dict[k1] += 1
                    else:
                        index_key_dict[k1] = 1
                    
                    if k2 in index_key_dict.keys():
                        index_key_dict[k2] += 1
                    else:
                        index_key_dict[k2] = 1
                    
                    recovered_key_dict[index] = index_key_dict

    keystream_length = max([len(cipher) for cipher in cipherset])
    recovered_key = []
    for index in range(keystream_length):

        if index in recovered_key_dict.keys():
            index_key_dict = recovered_key_dict[index]
            print(index, index_key_dict)
            keystream_byte = max(index_key_dict.items(), key=operator.itemgetter(1))[0]
            recovered_key.append(keystream_byte)
        else:
            recovered_key.append(None)

    return recovered_key


def ctr_encrypt_dataset(dataset):
	cipherset = []
	for data in dataset:
		cipherset.append(encrypt_ctr(nonce, key, data))

	return cipherset

def crack_ctr():
    cipherset = ctr_encrypt_dataset(dataset)
    recovered_key = crack_ctr_key_via_spaces(set(cipherset))
    cipher = list(cipherset)[37]
    decrypted = []
    recovered_key[0] = cipherset[0][0] ^ ord('I')
    recovered_key[30] = cipherset[27][30] ^ ord('e')
    recovered_key[31] = cipherset[27][31] ^ ord('n')
    recovered_key[33] = cipherset[37][33] ^ ord('t')
    recovered_key[34] = cipherset[37][34] ^ ord('u')
    recovered_key[35] = cipherset[37][35] ^ ord('r')
    recovered_key[36] = cipherset[37][36] ^ ord('n')
    recovered_key[37] = cipherset[37][37] ^ ord(',')
    for c,k in zip(cipher, recovered_key):
        if k:
            decrypted.append(c^k)
        else:
            decrypted.append(0)
    print(bytes(decrypted))
    print(bytes(recovered_key))
    
if __name__ == '__main__':
    crack_ctr()
