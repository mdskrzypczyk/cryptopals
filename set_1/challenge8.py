from challenge6 import breakup_cipher
data = open('8.txt').read().splitlines()
reps = []
for h in data:
	ascii = ''.join([chr(int(h[i:i+2], 16)) for i in range(0,len(h),2)])
	blocks = breakup_cipher(ascii, 16)
	rep = {}
	for block in blocks:
		if rep.get(block):
			rep[block] = rep[block]+1
		else:
			rep[block] = 1
	reps.append((rep,h))

#print(sorted(reps, key = lambda x : max(x[0].values()))[-1][0])