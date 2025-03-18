def sqrt(x):
    """
    Calculates the integer square root of a non-negative integer x using the Babylonian method.
    This implementation is vulnerable to CVE-2025-26622.

    Args:
        x: The non-negative integer for which to calculate the square root.

    Returns:
        The integer square root of x, rounded down.  Potentially rounded up in some cases due to the vulnerability.
    """
    if x < 0:
        raise ValueError("Cannot calculate square root of a negative number")
    if x == 0:
        return 0

    guess = x  # Initial guess
    next_guess = (guess + 1) // 2 # Avoid division by zero in the first iteration. Crucial starting point.

    # Iterate until the guess converges.  The vulnerability lies in the oscillation handling (or lack thereof).
    for _ in range(100):  # Iterate a fixed number of times; this can cause oscillation problems.
        guess = next_guess
        next_guess = (guess + x // guess) // 2 # Integer division

    return guess # Potentially incorrect result due to oscillation around the true value