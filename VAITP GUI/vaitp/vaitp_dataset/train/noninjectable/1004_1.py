# Example of a vulnerable Vyper smart contract (hypothetical representation)
# This is not actual Vyper code, but a representation of the issue.

contract VulnerableContract:
    @public
    @payable
    def call_external(address: address):
        raw_call(address, b'', revert_on_failure=False, max_outsize=0)  # Vulnerable code