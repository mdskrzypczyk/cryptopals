from binascii import unhexlify
from flask import Flask
from flask import request
from cipher_tools.hashing import sha1
from time import sleep
app = Flask(__name__)

def insecure_compare(sig1, sig2, delay):
    if len(sig1) != len(sig2):
        return "False", 500

    for b1, b2 in zip(sig1, sig2):
        if b1 != b2:
            return "False", 500
        sleep(delay)

    return "True", 200

@app.route('/challenge31/')
def challenge31_oracle():
    file = request.args.get('file')
    signature = request.args.get('signature')
    signature = unhexlify(signature)

    with open(file) as f:
        file_contents = f.read()
        byte_contents = bytes(file_contents, 'utf-8')

    computed_signature = sig_cache[file]
    print(computed_signature)
    return insecure_compare(signature, computed_signature, 0.05)

sig_cache = {}
@app.route('/challenge32/')
def challenge32_oracle():
    file = request.args.get('file')
    signature = request.args.get('signature')
    signature = unhexlify(signature)

    if file not in sig_cache.keys():
        with open(file) as f:
            file_contents = f.read()
            byte_contents = bytes(file_contents, 'utf-8')
            sig_cache[file] = sha1(byte_contents)
            print(sig_cache[file])

    return insecure_compare(signature, sig_cache[file], 0.005)
