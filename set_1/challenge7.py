from Crypto.Cipher import AES
from base64 import b64decode

key = "YELLOW SUBMARINE"
data = b64decode(open('7.txt').read())

aes = AES.AESCipher(key=key, mode=AES.MODE_ECB)
print(str(aes.decrypt(data), 'utf-8'))
