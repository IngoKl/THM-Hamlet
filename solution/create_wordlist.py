#!/bin/python3

import re
import sys

args = sys.argv

if len(args) < 5:
    sys.exit('generate_wordlist.py file min_length max_length onlylowercase')

with open(args[1], 'r') as f:
    hamlet = f.read()

tokens = re.findall(r'\w+', hamlet)
types = set(tokens)

min_length = int(args[2])
max_length = int(args[3])
lowercase = args[4].lower() in ('True', 'true', '1')

if lowercase:
    words = [w for w in types if len(w) >= min_length and len(w) <= max_length and w.islower()]
else:
    words = [w for w in types if len(w) >= min_length and len(w) <= max_length]

for w in words:
    print(w)
