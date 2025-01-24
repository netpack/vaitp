@public
def safe_function(amount: decimal):
    assert amount >= 0, "Amount must be non-negative"
    assert amount <= 100.0, "Amount exceeds maximum limit"
    
    total: decimal = 100.0
    total += amount