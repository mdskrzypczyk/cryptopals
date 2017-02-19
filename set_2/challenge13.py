from challenge10 import *
from challenge11 import gen_random_count

key = gen_random_count(16)

def profile_for(email, uid=10, role='user'):
	email = email.replace('&', '').replace('=', '')
	return '&'.join(['email='+email, 'uid='+str(uid), 'role='+role])

def encrypt_profile(iv, key, profile, enc_func):
	return enc_func(iv, key, profile)

def parse_profile(profile):
	profile_map = {}
	fields = str(profile, 'utf-8').split('&')
	for field in fields:
		key, value = tuple(field.split('='))
		if value.isdigit():
			profile_map[key] = int(value)
		else:
			profile_map[key] = value

	return profile_map

def decrypt_and_parse(iv, key, cprofile, dec_func):
	return parse_profile(dec_func(iv, key, cprofile))

def generate_encrypted_admin_user():
	iv = b'\x00'*16
	admin_block_profile = profile_for('fo@bar.comadmin' + '\x0b'*11)
	role_offset_profile = profile_for('foo11@bar.com')
	encrypted_admin = breakup_cipher(encrypt_profile(iv, key, bytes(admin_block_profile, 'utf-8'), encrypt_ecb),16)[1]
	cprofile = breakup_cipher(encrypt_profile(iv, key, bytes(role_offset_profile, 'utf-8'), encrypt_ecb),16)
	chopped = cprofile[:len(cprofile)-1]
	return b''.join(chopped + [encrypted_admin])

#generated_profile = generate_encrypted_admin_user()
#print(decrypt_and_parse(b'\x00'*16, key, generated_profile, decrypt_ecb))