# Example of a vulnerable Vyper function (not actual Vyper code, for illustration only)
# This function does not validate the bounds of the decimal argument
@public
def vulnerable_function(amount: decimal):
    # Logic that uses 'amount' without proper validation
    total: decimal = 100.0
    total += amount

# Fixed version with proper bounds validation
@public
def safe_function(amount: decimal):
    assert amount >= 0, "Amount must be non-negative"
    assert amount <= 100.0, "Amount exceeds maximum limit"
    
    total: decimal = 100.0
    total += amount