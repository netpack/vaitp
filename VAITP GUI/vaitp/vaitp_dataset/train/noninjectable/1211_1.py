# Example of a vulnerable code snippet in Vyper prior to version 0.4.0b1

start = -5
N = 10

# This loop would revert in Vyper versions 0.3.8 to 0.4.0b1
for i in range(start, start + N):
    print(i)