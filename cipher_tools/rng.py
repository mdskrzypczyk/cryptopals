MT19937_config = {
    'w': 32,
    'n': 624,
    'm': 397,
    'r': 31,
    'a': 0x9908B0DF,
    'u': 11,
    'd': 0xFFFFFFFF,
    's': 7,
    'b': 0x9D2C5680,
    't': 15,
    'c': 0xEFC60000,
    'l': 18,
    'f': 1812433253
}

def mersenne_seed(seed, config):
    MT = [seed]
    for i in range(1, config['n']):
        value = config['f'] * (MT[i-1] ^ MT[i-1] >> (config['w'] - 2)) + i
        value &= int('1'*config['w'], 2)
        MT.append(value)
    return MT

def mersenne_twister_temper(x, config):
    y = x ^ ((x >> config['u']) & config['d'])
    y ^= ((y << config['s']) & config['b'])
    y ^= ((y << config['t']) & config['c'])
    y ^= (y >> config['l']) & int('1'*config['w'], 2)
    return y

def mersenne_twist(MT, config):
    um = 1 << (config['r'])
    lm = um ^ int('1' * config['w'], 2)

    for i in range(config['n']):
        y = ((MT[i] & um) + (MT[(i+1) % config['n']] & lm))
        MT[i] = MT[(i + config['m']) % config['n']] ^ y >> 1
        if y % 2:
            MT[i] = MT[i] ^ config['a']
    return MT

def mersenne_twister_rng(seed, config, index):
    MT = mersenne_seed(seed, config)
    MT = mersenne_twist(MT, config)
    while index >= config['n']:
        MT = mersenne_twist(MT, config)
        index -= config['n']

    return mersenne_twister_temper(MT[index], config)

