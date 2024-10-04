# This code uses a hash table to store user input without checking the hash secret
import sys
table = {}
while True:
    s = input("Enter a string: ")
    if s == "quit":
        break
    h = hash(s) # This uses the last eight bits of the prefix to randomize hash values
    print(f"The hash of {s} is {h}")
    if h in table:
        print(f"Collision detected with {table[h]}")
        sys.exit(1)
    else:
        table[h] = s