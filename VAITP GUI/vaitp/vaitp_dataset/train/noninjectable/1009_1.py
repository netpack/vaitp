# Vyper smart contract demonstrating the CVE-2023-32675 vulnerability

# This contract has multiple nonpayable functions and a nonpayable default function
contract VulnerableContract:
    @public
    @nonpayable
    def __default__():
        # This function is marked as nonpayable but can still receive funds
        pass

    @public
    @nonpayable
    def regular_function_one():
        # Regular nonpayable function
        pass

    @public
    @nonpayable
    def regular_function_two():
        # Another regular nonpayable function
        pass