from cipher_tools.padding import pkcs7pad
def challenge9():
	data = b'YELLOW SUBMARINE'
	return pkcs7pad(data, 20)

from base64 import b64decode
from cipher_tools.decryption import decrypt_cbc
def challenge10():
	iv = bytes(16)
	key = b'YELLOW SUBMARINE'
	with open('challenge_data/10.txt') as f:
		data = b64decode(f.read())
	return decrypt_cbc(iv, key, data, pad=True)

from cipher_tools.oracles import challenge11_oracle
from cipher_tools.cracking import identify_oracle_encryption
def challenge11():
	return identify_oracle_encryption(challenge11_oracle)

from cipher_tools.oracles import challenge12_oracle
from cipher_tools.cracking import crack_challenge12_oracle
def challenge12():
	return crack_challenge12_oracle(challenge12_oracle)

from cipher_tools.cracking import generate_encrypted_admin_user
def challenge13():
	return generate_encrypted_admin_user()

from cipher_tools.oracles import challenge14_oracle
from cipher_tools.cracking import crack_challenge14_oracle
def challenge14():
	return crack_challenge14_oracle(challenge14_oracle)

from cipher_tools.padding import pkcs7pad_verify
def challenge15():
	result_1 = pkcs7pad_verify(b'ICE ICE BABY\x04\x04\x04\x04', 16)
	result_2 = pkcs7pad_verify(b'ICE ICE BABY\x05\x05\x05\x05', 16)
	result_3 = pkcs7pad_verify(b'ICE ICE BABY\x01\x02\x03\x04', 16)
	return (result_1, result_2, result_3)

from cipher_tools.oracles import challenge16_oracle, challenge16_check_answer
from cipher_tools.cracking import crack_challenge16_oracle
def challenge16():
	return crack_challenge16_oracle(challenge16_oracle, challenge16_check_answer)

