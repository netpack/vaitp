# Example of a vulnerable function in Vyper
# This function does not validate the return value to be within int128 bounds
@public
def returns_int128() -> int128:
    return some_complex_calculation()  # Vulnerable to returning out-of-bounds int128

# Fixed version of the function with validation
@public
def returns_int128() -> int128:
    result: int128 = some_complex_calculation()
    assert result >= -2**127 and result < 2**127, "Result is out of int128 bounds"
    return result