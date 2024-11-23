# Example of using fastecdsa safely after the vulnerability fix

from fastecdsa import curve, ecdsa

# Properly initialize variables before use
def safe_curvemath_mul(point, scalar):
    if point is None or scalar is None:
        raise ValueError("Point and scalar must not be None")
    
    # Perform multiplication safely
    return point * scalar

# Example usage
try:
    G = curve.P256.G  # Get a base point from the curve
    k = 123456789     # Example scalar
    result = safe_curvemath_mul(G, k)
    print("Result:", result)
except Exception as e:
    print("Error:", e)