# Example of a Vyper smart contract demonstrating the vulnerability
@public
@payable
def vulnerable_function(target: address):
    raw_call(target, b'', value=msg.value)  # The value is ignored in delegatecall/staticcall