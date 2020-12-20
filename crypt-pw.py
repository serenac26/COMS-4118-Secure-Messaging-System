#!/usr/bin/python3

import crypt
import secrets
import sys

with open('/usr/share/dict/words') as f:
    words = [word.strip() for word in f]

for i in sys.argv[1:]:
	pw = '_'.join(secrets.choice(words) for i in range(2))
	hpw = crypt.crypt(pw, salt=None)
	print(i, hpw, pw)