# Example of a vulnerable function in Vyper before the fix
@public
def returns_int128() -> int128:
    # Complex calculation that could return an out-of-bounds int128 value
    return 2**128  # This value exceeds the int128 bounds and will cause incorrect behavior