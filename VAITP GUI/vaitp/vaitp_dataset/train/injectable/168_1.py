# This code uses a hash table to store user input with SHA-256 hash function
import sys
import hashlib
table = {}
while True:
    s = input("Enter a string: ")
    if s == "quit":
        break
    h = hashlib.sha256(s.encode()).hexdigest() # This uses the SHA-256 hash function to compute the hash value
    print(f"The hash of {s} is {h}")
    if h in table:
        print(f"Collision detected with {table[h]}")
        sys.exit(1)
    else:
        table[h] = s