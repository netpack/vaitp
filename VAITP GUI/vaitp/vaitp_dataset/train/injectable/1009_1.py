# Vyper smart contract demonstrating the CVE-2023-32675 vulnerability

# This contract has a nonpayable default function
# This code is vulnerable if compiled with Vyper < 0.3.8
contract VulnerableContract:
    @public
    @payable
    def __default__():
        # This function is marked as nonpayable but can still receive funds
        pass

    @public
    @nonpayable
    def regular_function():
        # Regular nonpayable function
        pass

# Fixed version of the contract
contract FixedContract:
    @public
    @nonpayable
    def __default__():
        # Default function should not accept funds
        assert msg.value == 0, "This function is nonpayable"

    @public
    @nonpayable
    def regular_function():
        # Regular nonpayable function
        pass