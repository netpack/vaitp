def sqrt_fixed(x: int) -> int:
    """
    Calculates the integer square root of x using the Babylonian method.
    This implementation addresses potential oscillation issues by
    adding a check to ensure the result is not rounded up incorrectly.
    """
    if x < 0:
        raise ValueError("Cannot calculate square root of negative number")
    if x == 0:
        return 0

    y = x
    z = (x + 1) // 2
    while z < y:
        y = z
        z = (x // z + z) // 2

    # Crucial check to prevent incorrect rounding up due to oscillation.
    # We check if (y+1)^2 <= x. If it's not, then y is the correct value.
    if (y + 1)**2 <= x:
       return y + 1
    else:
       return y