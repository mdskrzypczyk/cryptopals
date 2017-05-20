def generate_encrypted_admin_user():
	iv = b'\x00'*16
	key = bytes([randint(0,255) for i in range(16)])
	admin_block_profile = profile_for('fo@bar.comadmin' + '\x0b'*11)
	role_offset_profile = profile_for('foo11@bar.com')
	encrypted_admin = breakup_data(encrypt_profile(iv, key, bytes(admin_block_profile, 'utf-8'), encrypt_ecb),16)[1]
	cprofile = breakup_data(encrypt_profile(iv, key, bytes(role_offset_profile, 'utf-8'), encrypt_ecb),16)
	chopped = cprofile[:len(cprofile)-1]
	return b''.join(chopped + [encrypted_admin])

#generated_profile = generate_encrypted_admin_user()
#print(decrypt_and_parse(b'\x00'*16, key, generated_profile, decrypt_ecb))