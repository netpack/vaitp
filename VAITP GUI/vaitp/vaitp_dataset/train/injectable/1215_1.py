# Example of a Vyper smart contract demonstrating the fix for the vulnerability

# Version 0.3.0 or later is required to ensure non-reentrancy in default functions

@public
@nonreentrant('lock')
@payable
def default() -> uint256:
    # Logic that should not be reentrant
    return 1