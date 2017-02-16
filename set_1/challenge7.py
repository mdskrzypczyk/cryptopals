from Crypto.Cipher import AES
from base64 import b64decode

def decrypt_ecb(iv, key, data):
	aes = AES.AESCipher(IV=iv, key=key, mode=AES.MODE_ECB)
	return str(aes.decrypt(data), 'utf-8')

def encrypt_ecb(iv, key, data):
	aes = AES.AESCipher(IV=iv, key=key, mode=AES.MODE_ECB)
	return str(aes.encrypt(data), 'utf-8')

iv = '\x00'*16
key = "YELLOW SUBMARINE"
data = b64decode(open('7.txt').read())
print(decrypt_ecb(iv, key, data))