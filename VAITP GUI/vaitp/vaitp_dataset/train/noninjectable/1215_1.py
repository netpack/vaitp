# Example of a Vyper smart contract demonstrating the vulnerability before it was fixed

@public
@payable
def default() -> uint256:
    # Logic that is vulnerable to reentrancy attacks
    return 1