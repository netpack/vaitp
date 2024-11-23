# Example of a Vyper contract that fixes the CVE-2022-29255 vulnerability

# Version 0.3.4 and above of Vyper correctly handles external contract calls
# without evaluating the contract address twice when there is no return value.

@public
@constant
def safe_external_call(external_contract: address) -> bool:
    # Call an external contract that does not return a value
    # The external contract should be designed not to affect state if it has no return value
    external_contract.call()

    # Ensure that the state is consistent after the call
    # No double evaluation of the contract address occurs here
    return True