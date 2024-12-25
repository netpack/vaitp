# import sys
b = bytearray(b" " * (2**10))
try:
    b.extend(b" " * (2**10))
except OverflowError:
    print("Overflow error")
except Exception as e:
    print(e)

