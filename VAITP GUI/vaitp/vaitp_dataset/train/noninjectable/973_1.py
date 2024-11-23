# Example of a Vyper contract that demonstrates the CVE-2022-29255 vulnerability

@public
def vulnerable_external_call(external_contract: address):
    # Calling an external contract that does not return a value
    # This could lead to the external contract address being evaluated twice
    external_contract.call()

    # Potential side effects of the external contract call may occur here
    # If the external call has side effects, they could be applied multiple times