# Example of a vulnerable Vyper smart contract (not executable in Python)
# This is a representation of the vulnerability CVE-2023-32058

# Vyper version < 0.3.8
# @version ^0.3.7

# contract Vulnerable:
#     @public
#     @pure
#     def vulnerable_function(a: uint256, N: uint256) -> uint256:
#         total: uint256 = 0
#         for i in range(a, a + N):
#             total += i  # This could overflow if (a + N) exceeds the uint256 limit
#         return total

# Fixed version in Vyper >= 0.3.8
# @version ^0.3.8

contract Fixed:
    @public
    @pure
    def fixed_function(a: uint256, N: uint256) -> uint256:
        assert a + N <= 2**256 - 1  # Check for overflow before the loop
        total: uint256 = 0
        for i in range(a, a + N):
            total += i
        return total