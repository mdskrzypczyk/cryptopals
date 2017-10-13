import json
import base64
from binascii import unhexlify
from flask import Flask
from flask import request
from cipher_tools.encryption import encrypt_rsa
from cipher_tools.decryption import decrypt_rsa
from cipher_tools.hashing import sha1, sha256
from cipher_tools.mathlib import gen_rsa_keys
from urllib.parse import unquote
from time import sleep, time
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

cache = {}
while True:
    try:
        challenge41_keys = gen_rsa_keys()
        break
    except:
        pass
@app.route('/challenge41/', methods=['GET', 'POST'])
def challenge41_oracle():
    d = request.get_json(silent=True)
    cipher = base64.b64decode(d['cipher'])

    priv_key = challenge41_keys[1]
    byte_data = decrypt_rsa(cipher, priv_key[0], priv_key[1])
    hash = sha256(byte_data)

    if hash in cache.keys():
        return "Bad", 500

    else:
        cache[hash] = byte_data

        response = app.response_class(
            response=json.dumps({'data': str(base64.b64encode(byte_data), 'utf-8')}),
            status=200,
            mimetype='application/json'
        )

        return response

@app.route('/challenge41/get_message_and_pub')
def challenge41_get_message():
    secret = 'secretmessage'
    timestamp = time()
    byte_message = bytes(json.dumps({'timestamp': timestamp, 'data': secret}), 'utf-8')
    cache[sha256(byte_message)] = byte_message

    pub_key = challenge41_keys[0]
    cipher = encrypt_rsa(byte_message, pub_key[0], pub_key[1])

    data = {'cipher': str(base64.b64encode(cipher), 'utf8'), 'keys': pub_key}
    response = app.response_class(
        response=json.dumps(data),
        status=200,
        mimetype='application/json'
    )

    return response
