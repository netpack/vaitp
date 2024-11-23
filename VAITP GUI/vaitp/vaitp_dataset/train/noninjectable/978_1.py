# Example of a vulnerable Vyper function (not actual Vyper code, for illustration only)
@public
def vulnerable_function(amount: decimal):
    # Logic that uses 'amount' without proper validation
    total: decimal = 100.0
    total += amount