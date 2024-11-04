# Vulnerable Vyper code using raw_call Using # type: ignore due to Vyper programming language
@public
def vulnerable_function(value: uint256):
    # This call can lead to memory corruption if 'value' is a complex expression
    raw_call(msg.sender, msg.data, value, 0)