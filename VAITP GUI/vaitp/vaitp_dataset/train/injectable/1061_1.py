# Example of a Vyper smart contract demonstrating the vulnerability
# This is for illustrative purposes only and does not represent a fix

@public
@payable
def vulnerable_function(target: address):
    raw_call(target, b'', value=msg.value)  # The value is ignored in delegatecall/staticcall

# Fixed version in a newer Vyper version would ensure that value cannot be passed in delegatecall/staticcall
@public
@payable
def safe_function(target: address):
    assert msg.value == 0, "Value cannot be sent with delegatecall/staticcall"
    raw_call(target, b'')